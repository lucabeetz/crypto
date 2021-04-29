import hashlib
from crypto.sha256 import sha256
from crypto.ripemd160 import ripemd160
from crypto.private_key import gen_private_key
from crypto.public_key import gen_public_key

CODE_STRING = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE_COUNT = len(CODE_STRING)


def b58_encode(b):
    n = int.from_bytes(b, 'big')
    encode = ''

    while n >= BASE_COUNT:
        mod = int(n % BASE_COUNT)
        encode = CODE_STRING[mod] + encode
        n = n / BASE_COUNT

    if n:
        encode = CODE_STRING[int(n)] + encode

    return encode


def public_key_to_address_bytes(public_key):
    """
    Create a bitcoin address from a compressed public key
    """

    # Compress public key
    prefix = b'\x02' if public_key.y % 2 == 0 else b'\x03'
    pkb = prefix + public_key.x.to_bytes(32, 'big')

    pkb_hash = ripemd160(sha256(pkb))

    ver_pkb = b'\x00' + pkb_hash

    checksum = sha256(sha256(ver_pkb))[:4]
    pkb_check = ver_pkb + checksum

    return pkb_check


def public_key_to_address(public_key):
    b = public_key_to_address_bytes(public_key)
    b58_address = b58_encode(b)
    return b58_address
