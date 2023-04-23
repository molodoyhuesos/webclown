from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Hash import SHAKE256
from base64 import b16encode
from typing import *


class Node:
	"""
	Node() structure keeps 3 main values: public key, node_id (1024bit SHAKE256 hash of node's public key), RSA 2048-bit
	public key
	It is used in almost every WebClown's module
	"""
	key: RSA.RsaKey
	node_id: str
	ip: str

	def __init__(self, pubkey_: Union[RsaKey, str, bytes], ip: str):
		"""
		:param pubkey_: RSA public key of DEP, PEM or Pycryptodome.RSA.RsaKey instance format
		:param ip: IP address of Node. IPs are usually dynamics, so if no connection was established, we just run
		search again until we find needed node_id with updated IP address
		"""

		if pubkey_.__class__ == bytes:
			pubkey = RSA.import_key(pubkey_.decode())
		elif pubkey_.__class__ == str:
			pubkey = RSA.import_key(pubkey_)
		else:
			pubkey = pubkey_

		if not pubkey.can_encrypt():
			raise TypeError("Invalid public key")

		self.key = pubkey
		self.node_id = b16encode(SHAKE256.new(pubkey.export_key("DER")).read(1024)).decode()
		self.ip = ip


class PrivateNode(Node):
	"""
	Difference between Node is that "key" value is now a keypair of private/public keys
	"""

	def __init__(self, keypair: RsaKey, ip: str, nodebook_fn: str = "nodebook.db"):
		if not keypair.has_private():
			raise TypeError("Public/Private key instance required")

		super().__init__(keypair, ip)