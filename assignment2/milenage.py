from helpers import *

# network authentication function
def f1(
    k: bytes,
    temp: bytes,
    in1: bytes,
    opc: bytes,
    rot_bits: int,
    con: bytes,
) -> str:
    tmp = rot(xor(in1, opc), rot_bits)
    tmp = xor(temp, tmp)
    tmp = xor(tmp, con)
    tmp = encrypt(k, tmp)
    out = xor(tmp, opc)

    return byte_to_hex(bytes(out[:8]))

# response function
def f2(
    key: bytes,
    temp: bytes,
    opc: bytes,
    rot_bits: int,
    con: bytes,
) -> str:
    tmp = rot(xor(temp, opc), rot_bits)
    tmp = xor(tmp, con)
    tmp = encrypt(key, tmp)
    out = xor(tmp, opc)

    return byte_to_hex(bytes(out[8:]))

# kdf for CK
def f3(
    key: bytes,
    temp: bytes,
    opc: bytes,
    rot_bits: int,
    con: bytes,
) -> str:
    tmp = rot(xor(temp, opc), rot_bits)
    tmp = xor(tmp, con)
    tmp = encrypt(key, tmp)
    out = xor(tmp, opc)

    return byte_to_hex(bytes(out))

# kdf for IK
def f4(
    key: bytes,
    temp: bytes,
    opc: bytes,
    rot_bits: int,
    con: bytes,
) -> str:
    tmp = rot(xor(temp, opc), rot_bits)
    tmp = xor(tmp, con)
    tmp = encrypt(key, tmp)
    out = xor(tmp, opc)

    return byte_to_hex(bytes(out))

# kdf for AK
def f5(
    key: bytes,
    temp: bytes,
    opc: bytes,
    rot_bits: int,
    con: bytes,
) -> str:
    tmp = rot(xor(temp, opc), rot_bits)
    tmp = xor(tmp, con)
    tmp = encrypt(key, tmp)
    out = xor(tmp, opc)

    return byte_to_hex(bytes(out[:6]))