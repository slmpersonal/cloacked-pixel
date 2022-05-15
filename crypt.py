import hashlib
import base64
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES

'''
Thanks to
https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
'''
class AESCipher:

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(b'16-character key').digest()	# 32 bit digest

    def encrypt(self, raw):
        raw = base64.b64encode(self._pad(raw.encode('utf8')))
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key=self.key, mode= AES.MODE_CFB,iv= iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


#%%

#%%
