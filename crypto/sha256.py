import math


def genH():
    return [frac_bin(p ** (1/2.0)) for p in gen_primes(8)]


def genK():
    return [frac_bin(p ** (1/3.0)) for p in gen_primes(64)]


def Ch(x, y, z):
    return (x & y) ^ (~x & z)


def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def capsig0(x):
    return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))


def capsig1(x):
    return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))


def sig0(x):
    return (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3))


def sig1(x):
    return (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10))


def is_prime(x):
    return sum([x % i == 0 for i in range(1, x+1)]) == 2


def gen_primes(n):
    primes = []
    i = 2
    while len(primes) < n:
        if is_prime(i):
            primes.append(i)
        i += 1

    return primes


def frac_bin(f, n=32):
    f -= math.floor(f)
    f *= 2**n
    f = int(f)
    return f


def rotr(x, n, size=32):
    return (x >> n) | (x << size - n) & (2**size - 1)


def shr(x, n):
    return (x >> n)


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


def sha256(b):
    b = pad(b)
    blocks = parse(b)

    K = genK()
    H = genH()

    for block in blocks:
        W = []
        for t in range(64):
            if t <= 15:
                W.append(bytes(block[t*4:t*4+4]))
            else:
                term = (sig1(b2i(W[t-2])) + b2i(W[t-7]) +
                        sig0(b2i(W[t-15])) + b2i(W[t-16])) % 2**32
                W.append(i2b(term))

        a, b, c, d, e, f, g, h = H

        for t in range(64):
            T1 = (h + capsig1(e) + Ch(e, f, g) + K[t] + b2i(W[t])) % 2**32
            T2 = (capsig0(a) + Maj(a, b, c)) % 2**32
            h = g
            g = f
            f = e
            e = (d + T1) % 2**32
            d = c
            c = b
            b = a
            a = (T1 + T2) % 2**32

        H[0] = a + H[0]
        H[1] = b + H[1]
        H[2] = c + H[2]
        H[3] = d + H[3]
        H[4] = e + H[4]
        H[5] = f + H[5]
        H[6] = g + H[6]
        H[7] = h + H[7]

        H = [i % 2**32 for i in H]

    return b''.join(i2b(i) for i in H)
