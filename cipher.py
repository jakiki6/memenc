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
        while len(s) % self.bs:
            s += bytes([random.randint(0, 255)])
        return s

    def _unpad(self, s):
        while len(s) % self.bs:
            s = s[:-1]
        return s

def encrypt(data: bytes):
    cipher = AESCipher(bytes(14) + bytes([random.randint(0, 255), random.randint(0, 255)]))

    data = bytearray(b"\x69" + cipher.encrypt(bytes(16)) + cipher.encrypt(data))

    xor = random.randint(0, 256)
    for i in range(0, len(data)):
        data[i] ^= xor

    return data

def decrypt(data: bytes):
    for xor in range(0, 256):
        if data[0] ^ xor == 0x69:
            print(f"found xor 0x{hex(xor)[2:].zfill(2)}")
            data = bytearray(data[1:])
            for i in range(0, len(data)):
                data[i] ^= xor
            break

    for key in range(0, 65536):
        cipher = AESCipher(bytes(14) + bytes([key >> 8, key & 0xff]))
        if cipher.decrypt(data[:32]) == bytes(16):
            print(f"found key 0x{hex(key)[2:].zfill(4)}")
            data = cipher.decrypt(data[16:])
            return data
            
    raise ValueError("key not found :(")
