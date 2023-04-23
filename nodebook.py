from sqlite3 import connect, Connection
from node import Node
from Crypto.PublicKey import RSA
from os import access, F_OK, R_OK, W_OK
from encryptor import AESEncryptor
from hashlib import sha256
from typing import *


def _save_close(db: Connection, passphrase: str, fn: str) -> NoReturn:
	data = b""
	for i in db.iterdump():
		data += i.encode() + b"\n"
	db.close()
	aesenc = AESEncryptor()
	iv = aesenc.init(sha256(passphrase.encode()).digest())
	data = aesenc.encrypt(data)
	del aesenc
	with open(fn, "wb") as x:
		x.write(iv + data)


def _save_open(passphrase: str, fn: str) -> Connection:
	with open(fn, "rb") as x:
		data = x.read()
		iv = data[:16]
		data = data[16:]
	aesenc = AESEncryptor()
	aesenc.init(sha256(passphrase.encode()).digest(), iv)
	data = aesenc.decrypt(data).decode()
	print(data)
	del aesenc
	db = connect(":memory:")
	db.executescript(data)
	return db


class NodeBook:
	"""SQLite db wrapper with additional AES secure measures"""
	db: Connection
	nodes: list
	_fn: str

	def __init__(self, fn: str = "nodebook.db", passphrase: str = None):
		"""
		:param fn: DB filename to be saved or opened from
		:param passphrase: Passphrase for database, any length
		"""

		if not access(fn, F_OK):
			self.db = connect(":memory:", isolation_level=None)
			self.db.execute("CREATE TABLE nodes(node_id text, node_ip text, node_pubkey text);")
		else:
			if not passphrase:
				raise TypeError("No passphrase given")
			self.db = _save_open(passphrase, fn)
		self._fn = fn

	def get_node(self, node_id_: str) -> Node:
		"""
		:param node_id_: Node ID
		:return: Node instance
		"""

		node_id = node_id_.replace('"', "").replace("'", "")
		for nid, nip, npubkey in self.nodes:
			if node_id == nid:
				return Node(npubkey, nip)

	def get_all_nodes(self) -> List[Node]:
		"""
		:return: Array of all Node's, that nodebook contains
		"""

		c = self.db.cursor()
		c.execute("SELECT * from nodes")
		d = c.fetchall()
		c.close()
		return [Node(i[2], i[1]) for i in d]

	def add_node(self, node_: Node) -> bool:
		"""
		:param node_: Node instance to be added into DB
		:return: Success state, True if successful, False if not
		"""

		node_id_ = node_.node_id
		node_ip_ = node_.ip
		node_pubkey = node_.key

		node_id = node_id_.replace('"', "").replace("'", "")
		node_ip = node_ip_.replace('"', "").replace("'", "")
		c = self.db.cursor()
		c.execute(f"SELECT * FROM nodes WHERE node_id='{node_id}'")
		if c.fetchone():
			return False

		c.execute(f"INSERT INTO nodes VALUES ('{node_id}', '{node_ip}', '{node_pubkey.export_key().decode()}')")
		c.close()
		return True

	def save_close(self, passphrase: str) -> None:
		"""
		:param passphrase: Passphrase to encrypt/save DB with. DB filename is the same as used in __init__().
		Whatever passphrase is given, next time opening DB will require this passphrase
		:return: None
		"""

		_save_close(self.db, passphrase, self._fn)





