from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA3_384
from random import randbytes
from typing import *
from os import access, F_OK, R_OK, W_OK
from pickle import loads, dumps


class AESEncryptor:
	"""
	Basic Pycryptodome.Cipher.AES wrapper
	"""
	aes_core: AES

	def init(self, key: bytes, iv: bytes = None) -> bytes:
		"""
		:param key: AES key, 32 bytes long
		:param iv: If AESEncryptor will be needed for decrypting message with given key, IV must be passed as well
		since WebClown use CBC mode
		:return: IV
		"""
		if len(key) != 32:
			raise TypeError("key must be 32 bytes long")
		if not iv:
			iv = randbytes(16)
		self.aes_core = AES.new(key, AES.MODE_CBC, iv)
		return iv

	def encrypt(self, data: bytes) -> bytes:
		return self.aes_core.encrypt(pad(data, 16))

	def decrypt(self, data: bytes) -> bytes:
		return unpad(self.aes_core.decrypt(data), 16)


class RSASigner:
	"""
	Pycryptodome.PublicKey.RSA wrapper. Implements few methods of securing/signing given data
	"""
	rsa_core: RSA.RsaKey

	def __init__(self, action: Union[Literal["load_keys"], Literal["generate_keys"]],
				passphrase: str, private_fn: str = "private.pem", public_fn: str = "public.pem"):
		"""
		:param action: Must be either "load_keys" or "generate_keys", if first, "private_fn" and "public_fn" arguments must be passed
		:param passphrase: Guard passcode for private key file
		:param private_fn: Filepath for private key file
		:param public_fn: Filepath for public key file
		"""

		if action == "load_keys":
			self._load_keys(passphrase, private_fn, public_fn)
		elif action == "generate_keys":
			self._generate_new_keys(passphrase, private_fn, public_fn)
		else:
			raise TypeError("'action' argument must be either 'load_keys' or 'generate_keys'")

	def _save_keys(self, passphrase: str, private_fn: str, public_fn: str) -> NoReturn:
		"""
		Protected function. It's not recommended to use after __init__()'s called
		:param passphrase: Guard passphrase for private key file
		:param private_fn: Filepath for private key file
		:param public_fn: Filepath for public key file
		:return: None
		"""

		private = self.rsa_core.export_key("PEM", passphrase)
		public = self.rsa_core.public_key().export_key("PEM")
		with open(private_fn, "w") as x, open(public_fn, "w") as y:
			x.write(private.decode())
			y.write(public.decode())

	def _generate_new_keys(self, passphrase: str, private_fn: str, public_fn: str) -> NoReturn:
		"""
		Protected function. It's not recommended to use after __init__()'s called
		:param passphrase: Guard passphrase for private key file
		:param private_fn: Filepath for private key file
		:param public_fn: Filepath for public key file
		:return: None
		"""

		self.rsa_core = RSA.generate(4096)
		self._save_keys(passphrase, private_fn, public_fn)

	def _load_keys(self, passphrase: str, private_fn: str, public_fn: str) -> NoReturn:
		"""
		Protected function. It's not recommended to use after __init__()'s called
		:param passphrase: Guard passphrase for private key file
		:param private_fn: Filepath for private key file
		:param public_fn: Filepath for public key file
		:return: None
		"""

		if not access(private_fn, F_OK | R_OK) or not access(public_fn, F_OK | R_OK):
			raise PermissionError("Cannot access key files")

		with open(private_fn, "r") as x, open(public_fn, "r") as y:
			try:
				self.rsa_core = RSA.import_key(x.read(), passphrase)
				self.rsa_core.publickey = RSA.import_key(y.read())
			except ValueError:
				raise PermissionError("Passphrase is incorrect or key files are damaged")

	def encrypt(self, data: bytes, pubkey: RSA.RsaKey = None) -> bytes:
		"""
		:param data: Data to encrypt
		:param pubkey: If not passed, loaded key's public key will be used
		:return:
		"""
		oaep = PKCS1_OAEP.new(pubkey or self.rsa_core)
		return oaep.encrypt(data)

	def decrypt(self, data: bytes) -> bytes:
		"""
		:param data: Data to decrypt. Private key is used
		:return:
		"""
		oaep = PKCS1_OAEP.new(self.rsa_core)
		return oaep.decrypt(data)

	def sign(self, data: bytes) -> bytes:
		"""
		Sign given data with this AESEncryptor() instance's key
		:return: Signature (bytes), pass it with encrypted data so addressed user can verify it
		"""

		hashf = SHA3_384.new()
		hash = hashf.update(data)
		a = pkcs1_15.new(self.rsa_core)
		return a.sign(hash)

	@staticmethod
	def verify(data: bytes, pubkey: RSA.RsaKey, sign: bytes) -> bool:
		"""
		Verify if data is signed with given signature
		:param data: Data to be verified
		:param pubkey: Public key, which was used to create signature
		:param sign: Signature
		:return: boolean, if True, then given data is legitimate, if False, data is corrupted or compromised
		"""
		hashf = SHA3_384.new()
		hash = hashf.update(data)
		a = pkcs1_15.new(pubkey)
		try:
			a.verify(hash, sign)
			return True
		except ValueError:
			return False
