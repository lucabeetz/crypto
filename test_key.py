from crypto.public_key import gen_public_key
from crypto.private_key import gen_private_key


def test_public_key_gen():
    """
    Test generation of public key from private key
    Example taken from: https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc
    """

    private_key = 0x1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD
    public_key = gen_public_key(private_key)
    # Public key is a Point(x, y) on an elliptic curve
    assert public_key.x == 0xF028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A
    assert public_key.y == 0x07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB
