# Cryptography library import
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# defines rotation constants
r1 = 64
r2 = 0
r3 = 32
r4 = 64
r5 = 96

# defines constant values
c1 = bytes(16)
c2 = bytes(15) + b"\x01"
c3 = bytes(15) + b"\x02"
c4 = bytes(15) + b"\x04"
c5 = bytes(15) + b"\x08"

# converts bytes to hex
def byte_to_hex(b: bytes) -> str:
    return b.hex()

# converts hex to bytes
def hex_to_byte(h: str) -> bytes:
    return bytes.fromhex(h)

# XOR function
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(a, b))

# rotation function, rotates left. Made with help from ChatGPT
def rot(x, n):
    if len(x) != 16: raise ValueError
    r = (n >> 3) & 15
    return bytearray(x[r:] + x[:r])

# AES encryption function
# taken from "Milenage_2.pdf", slide 24
def encrypt(k: bytes, m: bytes) -> bytes:
    assert len(k) == 16, "Key must be 16 bytes long"
    assert len(m) == 16, "Input must be 16 bytes long"

    encryptor = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    return encryptor.update(m) + encryptor.finalize()

# removes whitespace and newlines from test set
def fix_hex(s):
    return s.replace(" ", "").replace("\n", "").lower()