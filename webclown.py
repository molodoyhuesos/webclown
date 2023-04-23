import node
import encryptor
from socket import socket


class WebClown:
	"""
	Main WebClown protocol's implementation
	"""

	def __init__(self, passphrase: str):
		"""
		:param passphrase: Unique passphrase, that will unlock notebook's database and decode private key file.
		Make it as long and difficult to brute as possible
		"""