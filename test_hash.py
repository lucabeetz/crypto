import hashlib
from crypto.sha256 import sha256


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
        assert y_target == y
