import os


def get_random_os(n=32):
    return os.urandom(n)


def gen_private_key():
    # Bitcoin elliptic curve order from https://en.bitcoin.it/wiki/Secp256k1
    _r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    while True:
        key = int.from_bytes(get_random_os(), 'big')
        if key < _r:
            break

    return key
