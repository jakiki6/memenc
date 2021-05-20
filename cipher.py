import base64
import hashlib
import random
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):
    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = key

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs).encode()

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def encrypt(data: bytes):
    cipher = AESCipher(bytes(14) + bytes([random.randint(0, 255), random.randint(0, 255)]))
    data = b"\x13\x37\x69\x69" + data

    return cipher.encrypt(data)

def decrypt(data: bytes):
    for key in range(0, 65536):
        cipher = AESCipher(bytes(14) + bytes([key >> 8, key & 0xff]))
        _data = cipher.decrypt(data)
        if _data.startswith(b"\x13\x37\x69\x69"):
            print(f"found key 0x{hex(key)[2:].zfill(4)}")
            return _data[4:]
    raise ValueError("key not found :(")