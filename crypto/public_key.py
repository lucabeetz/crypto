def extended_euclidian_algorithm(a: int, b: int):
    """
    Implementation of the extended euclidian algorithm
    Copied from https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode

    Arguments:
    a, b: Integers

    Returns (gcd, x, y) so that: a * x + b * y == gcd
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return (old_r, old_s, old_t)


def inv(n, p):
    """
    Return modular multiplicative index m
    (n * m) % p == 1
    """
    _, x, _ = extended_euclidian_algorithm(n, p)
    return x % p


class Curve:
    """
    Elliptic Curve
    """

    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b


class Point:
    """
    Point (x, y) on elliptic curve
    """

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y

    def __add__(self, other):
        """
        Addition of two Points on the curve
        Further explanation: https://www.cs.uaf.edu/2013/spring/cs463/lecture/03_25_ECC.html
        """
        if self == PAI:
            return other
        if other == PAI:
            return self
        if self.x == other.x and self.y != other.y:
            return PAI

        # Compute slope y = mx + v
        if self.x == other.x and self.y == other.y:
            # Two Points are the same -> Compute tangent on curve
            m = (3 * self.x**2) * inv(2 * self.y, self.curve.p)
        else:
            # Compute slope between two points
            m = (other.y - self.y) * inv(other.x - self.x, self.curve.p)

        v = self.y - m * self.x

        # New Point is at the intersection of the slop and the curve
        new_x = (m**2 - self.x - other.x) % self.curve.p
        new_y = (-(m * new_x + v)) % self.curve.p

        return Point(self.curve, new_x, new_y)

    def __mul__(self, k):
        """
        Multiplication of a Point with an integer
        This uses the 'double and add' algorithm described here under 'Scalar multiplication'
        https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/
        """
        assert isinstance(k, int) and k >= 0
        result = PAI
        append = self
        while k:
            if k & 1 == 1:
                result += append
            append += append
            k >>= 1
        return result


# Point at Infinity
PAI = Point(0, 0, 0)


def gen_curve():
    """
    Generate Curve and generator G used in the Bitcoin protocol
    https://en.bitcoin.it/wiki/Secp256k1
    """
    _p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    _b = 0x0000000000000000000000000000000000000000000000000000000000000007
    _a = 0x0000000000000000000000000000000000000000000000000000000000000000
    _Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    _Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    curve = Curve(_p, _a, _b)
    G = Point(curve, _Gx, _Gy)
    return curve, G


def gen_public_key(private_key):
    _, G = gen_curve()
    public_key = G * private_key
    return public_key
