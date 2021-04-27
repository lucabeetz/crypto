def genK():
    K = []
    for t in range(80):
        if t <= 19:
            K.append(0x5a827999)
        elif t <= 39:
            K.append(0x6ed9eba1)
        elif t <= 59:
            K.append(0x8f1bbcdc)
        elif t <= 79:
            K.append(0xca62c1d6)

    return K


def genH():
    return [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]


def rotl(x, n, size=32):
    return (x << n) | (x >> size - n) & (2**size - 1)


def b2i(b):
    return int.from_bytes(b, 'big')


def i2b(i):
    return i.to_bytes(4, 'big')


def pad(b):
    b = bytearray(b)
    l = len(b) * 8

    # Pad with 1 and 0s
    b.append(0b10000000)
    while not (len(b) * 8) == 448 % 512:
        b.append(0b00000000)

    # Last 64 bits are message length
    b.extend(l.to_bytes(8, 'big'))
    return b


def parse(b):
    words = []
    for i in range(0, len(b), 64):
        words.append(b[i:(i+64)])

    return words


def f(x, y, z, t):
    if t <= 19:
        return (x & y) ^ (~x & z)
    elif t <= 39:
        return x ^ y ^ z
    elif t <= 59:
        return (x & y) ^ (x & z) ^ (y & z)
    elif t <= 79:
        return x ^ y ^ z


def sha1(b):
    b = pad(b)
    blocks = parse(b)

    K = genK()
    H = genH()

    for block in blocks:
        W = []
        for t in range(80):
            if t <= 15:
                W.append(bytes(block[t*4:t*4+4]))
            else:
                term = b2i(W[t-3]) ^ b2i(W[t-8]) ^ b2i(W[t-14]) ^ b2i(W[t-16])
                W.append(i2b(rotl(term, 1) % 2**32))

        a, b, c, d, e = H

        for t in range(80):
            T = (rotl(a, 5) + f(b, c, d, t) + e + K[t] + b2i(W[t])) % 2**32
            e = d
            d = c
            c = rotl(b, 30) % 2**32
            b = a
            a = T

        H[0] = a + H[0]
        H[1] = b + H[1]
        H[2] = c + H[2]
        H[3] = d + H[3]
        H[4] = e + H[4]

        H = [i % 2**32 for i in H]

    return b''.join(i2b(i) for i in H)


if __name__ == '__main__':
    M = 'abc'.encode('ascii')
    sha1_hash = sha1(M)
    print(sha1_hash.hex())
