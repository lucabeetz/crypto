"""
Implementation of the RIPEMD160 hashing algorithm according to this document
https://academic.microsoft.com/paper/2615514828/citedby/search?q=RIPEMD-160%3A%20A%20Strengthened%20Version%20of%20RIPEMD&qe=RId%253D2615514828&f=&orderBy=0
"""


# -------------------- Constant declaration --------------------

def gen_r():
    r = []
    r.extend([j for j in range(16)])
    r.extend([7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8])
    r.extend([3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12])
    r.extend([1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2])
    r.extend([4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13])

    return r


def gen_r_prime():
    r = []
    r.extend([5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12])
    r.extend([6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2])
    r.extend([15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13])
    r.extend([8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14])
    r.extend([12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11])

    return r


def gen_s():
    s = []
    s.extend([11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8])
    s.extend([7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12])
    s.extend([11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5])
    s.extend([11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12])
    s.extend([9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6])

    return s


def gen_s_prime():
    s = []
    s.extend([8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6])
    s.extend([9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11])
    s.extend([9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5])
    s.extend([15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8])
    s.extend([8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11])

    return s


def gen_k():
    k = []
    for j in range(80):
        if j <= 15:
            k.append(0x00000000)
        elif j <= 31:
            k.append(0x5A827999)
        elif j <= 47:
            k.append(0x6ED9EBA1)
        elif j <= 63:
            k.append(0x8F1BBCDC)
        elif j <= 79:
            k.append(0xA953FD4E)

    return k


def gen_k_prime():
    k = []
    for j in range(80):
        if j <= 15:
            k.append(0x50A28BE6)
        elif j <= 31:
            k.append(0x5C4DD124)
        elif j <= 47:
            k.append(0x6D703EF3)
        elif j <= 63:
            k.append(0x7A6D76E9)
        elif j <= 79:
            k.append(0x00000000)

    return k


def gen_h():
    return [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]


def F(j, x, y, z):
    if j <= 15:
        return x ^ y ^ z
    elif j <= 31:
        return (x & y) | (~x & z)
    elif j <= 47:
        return (x | ~y) ^ z
    elif j <= 63:
        return (x & z) | (y & ~z)
    elif j <= 79:
        return x ^ (y | ~z)


# -------------------- Helper functions --------------------

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
    while (len(b) * 8) % 512 != 448:
        b.append(0b00000000)

    # Last 64 bits are message length
    b.extend(l.to_bytes(8, 'big'))
    return b


def parse(b):
    words = []
    for i in range(0, len(b), 64):
        words.append(b[i:(i+64)])

    return words


def ripemd160(b):
    b = pad(b)
    blocks = parse(b)

    H = gen_h()

    K = gen_k()
    K_p = gen_k_prime()

    s = gen_s()
    s_p = gen_s_prime()

    r = gen_r()
    r_p = gen_r_prime()

    for block in blocks:
        a, b, c, d, e = H
        a_p, b_p, c_p, d_p, e_p = H

        for j in range(80):
            T = (rotl((a + F(j, b, c, d) +
                       b2i(block[r[j]*4:r[j]*4+4]) + K[j]) % 2**32, s[j]) + e) % 2**32
            a = e
            e = d
            d = rotl(c, 10)
            c = b
            b = T

            T = (rotl((a_p + F(79 - j, b_p, c_p, d_p) +
                       b2i(block[r_p[j]*4:r_p[j]*4+4]) + K_p[j]) % 2**32, s_p[j]) + e_p) % 2**32

            a_p = e_p
            e_p = d_p
            d_p = rotl(c_p, 10)
            c_p = b_p
            b_p = T

        T = H[1] + c + d_p
        H[1] = H[2] + d + e_p
        H[2] = H[3] + e + a_p
        H[3] = H[4] + a + b_p
        H[4] = H[0] + b + c_p
        H[0] = T

        H = [i % 2**32 for i in H]

    return b''.join(i2b(i) for i in H)


if __name__ == '__main__':
    M = ''.encode('ascii')
    ripemd160 = ripemd160(M)
    print(ripemd160.hex())
