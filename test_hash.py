import hashlib
from crypto.sha256 import sha256
from crypto.sha1 import sha1


def test_sha256():
    test_bytes = [
        b'',
        b'abc',
        b'cat',
        b'longer sentence for validation of sha256 on large number of blocks' * 20
    ]

    for b in test_bytes:
        y_target = hashlib.sha256(b).hexdigest()
        y = sha256(b).hex()
        assert y == y_target


def test_sha1():
    test_bytes = [
        b'',
        b'abc',
        b'cat',
        b'longer sentence for validation of sha256 on large number of blocks' * 20
    ]

    for b in test_bytes:
        y_target = hashlib.sha1(b).hexdigest()
        y = sha1(b).hex()
        assert y == y_target
