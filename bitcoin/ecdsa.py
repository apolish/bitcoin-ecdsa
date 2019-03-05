#!/usr/bin/env python

import collections
import random
import hashlib

class Ecdsa(object):
    """ Elliptic Curve Digital Signature Algorithm (only for bitcoin case) """
    
    def __init__(self):
        """ Elliptic Curve 'secp256k1' parameters (only for bitcoin case): """
        EllipticCurve = collections.namedtuple("EllipticCurve", "name p a b g n h")
        self.__curve = EllipticCurve(
            "secp256k1",
            # Field characteristic:
            p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
            # Curve coefficients:
            a = 0,
            b = 7,
            # Base point:
            g = (
                # x - coordinate:
                0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                # y - coordinate:
                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
            ),
            # Subgroup order:
            n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            # Subgroup cofactor:
            h = 1
        )
    
    def __inverse_mod(self, k, p):
        """ Return the inverse of [k] modulo [p].
        This function returns the only integer [x] such that (x * k) % p == 1.
        [k] must be non-zero and [p] must be a prime. """
        if k == 0:
            raise ZeroDivisionError("division by zero")
        if k < 0:
            # k ** -1 = p - (-k) ** -1  (mod p)
            return p - self.__inverse_mod(-k, p)
        # Extended Euclidean algorithm.
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = p, k
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        gcd, x, _ = old_r, old_s, old_t # _:y
        assert gcd == 1
        assert (k * x) % p == 1
        return x % p
    
    def __is_on_curve(self, point):
        """ Returns True if the given point lies on the elliptic curve. """
        if point is None:
            # None represents the point at infinity.
            return True
        x, y = point
        return (y**2 - x**3 - self.__curve.a * x - self.__curve.b) % self.__curve.p == 0
    
    def __point_neg(self, point):
        """ Return -point. """
        if point is None:
            # -0 = 0
            return None
        x, y = point
        result = (x, -y % self.__curve.p)
        return result
    
    def __point_add(self, point1, point2):
        """ Return the result of point1 + point2 according to the group law. """
        if point1 is None:
            # 0 + point2 = point2
            return point2
        if point2 is None:
            # point1 + 0 = point1
            return point1
        x1, y1 = point1
        x2, y2 = point2
        if x1 == x2 and y1 != y2:
            # point1 + (-point1) = 0
            return None
        if x1 == x2:
            # This is the case point1 == point2.
            m = (3 * x1 * x1 + self.__curve.a) * self.__inverse_mod(2 * y1, self.__curve.p)
        else:
            # This is the case point1 != point2.
            m = (y1 - y2) * self.__inverse_mod(x1 - x2, self.__curve.p)
        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        result = (x3 % self.__curve.p, -y3 % self.__curve.p)
        return result

    def __scalar_multiply(self, k, point):
        """ Return [k * point] computed using the double and point_add algorithm. """
        if k % self.__curve.n == 0 or point is None:
            return None
        if k < 0:
            # k * point = -k * (-point)
            return self.__scalar_multiply(-k, self.__point_neg(point))
        result = None
        addend = point
        while k:
            if k & 1:
                # Add.
                result = self.__point_add(result, addend)
            # Double.
            addend = self.__point_add(addend, addend)
            k >>= 1
        assert self.__is_on_curve(result)
        return result

    def make_keypair(self, private_key = 0):
        """ Generate a random private-public key pair. """
        if private_key == 0:
            private_key = random.randrange(1, self.__curve.n - 1)
        public_key = self.__scalar_multiply(private_key, self.__curve.g)
        return private_key, public_key
    
    def public_key(self, public_key):
        """ Format and return uncompressed public key. """
        x = str(hex(public_key[0]))[2:]
        y = str(hex(public_key[1]))[2:]
        return "04" + x + y

    def __hash_message(self, message):
        """ Return the truncated SHA521 hash of the message. """
        message_hash = hashlib.sha512(message).digest()
        e = int.from_bytes(message_hash, "big")
        # FIPS 180 says that when a hash needs to be truncated, the rightmost bits
        # should be discarded.
        z = e >> (e.bit_length() - self.__curve.n.bit_length())
        assert z.bit_length() <= self.__curve.n.bit_length()
        return z

    def sign_message(self, k, private_key, message):
        """ Sign the message and return [r, s, z] structure. """
        z = self.__hash_message(message)
        r = 0
        s = 0
        while not r or not s:
            if k == 0:
                k = random.randrange(1, self.__curve.n - 1)
            x, _ = self.__scalar_multiply(k, self.__curve.g) # _:y
            r = x % self.__curve.n
            c = self.__inverse_mod(k, self.__curve.n)
            s = ((z + r * private_key) * c) % self.__curve.n
        return (r, s, z)

    def verify_signature(self, public_key, signature):
        """ Verify the message and return the result. """
        r, s, z = signature
        w = self.__inverse_mod(s, self.__curve.n)
        u1 = (z * w) % self.__curve.n
        u2 = (r * w) % self.__curve.n
        x, _ = self.__point_add( # _:y
            self.__scalar_multiply(u1, self.__curve.g),
            self.__scalar_multiply(u2, public_key)
        )
        if (r % self.__curve.n) == (x % self.__curve.n):
            return True # Signature matches!
        else:
            return False # Invalid signature!


if __name__ == "__main__":
    ecdsa = Ecdsa()

    print("")
    print("[1] Generate a new key pair (private and public key) randomly:")
    private_key, public_key = ecdsa.make_keypair()
    print("Private key:")
    print("  d = %s" % str(hex(private_key))[2:])
    print("Public key:")
    print("  x = %s" % str(hex(public_key[0]))[2:])
    print("  y = %s" % str(hex(public_key[1]))[2:])
    
    print("")
    print("[2] Generate only public key if private key is known:")
    private_key = int("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725", 16) 
    _, public_key = ecdsa.make_keypair(private_key)
    Q = ecdsa.public_key(public_key)
    print("Private key:")
    print("  d = %s" % str(hex(private_key))[2:])
    print("Public key:")
    print("  x = %s" % str(hex(public_key[0]))[2:]) # 'x-coordinate' of bitcoin public key.
    print("  y = %s" % str(hex(public_key[1]))[2:]) # 'y-coordinate' of bitcoin public key.
    print("  Q = %s" % Q) # 'pubKey' (uncompresed bitcoin public key) in bitcoin transaction.

    print("")
    print("[3] Sign some message and verificate it:")
    message = b"Hello!"
    private_key = int("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725", 16) 
    signature = ecdsa.sign_message(0, private_key, message)
    print("Signature:")
    print("  r = %s" % str(hex(signature[0]))[2:]) # 'sigR' in bitcoin transaction.
    print("  s = %s" % str(hex(signature[1]))[2:]) # 'sigS' in bitcoin transaction.
    print("  z = %s" % str(hex(signature[2]))[2:]) # 'sigZ' (message digest) in bitcoin transaction.
    print("Verification: %s" % ecdsa.verify_signature(public_key, signature))

    print("")
    print("[4] Verify some bitcoin transaction (for example):")
    print("  txid: cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79")
    """ 
        For example:
        https://2coin.org/index.html?txid=cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79
        {
            "txid": "cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79",
            [...]
            "sigR": "009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc413287",
            "sigS": "1aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e",
            "sigZ": "c2d48f45d7fbeff644ddb72b0f60df6c275f0943444d7df8cc851b3d55782669",
            "pubKey": "042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabb"
            [...]
        }
    """
    r = int("009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc413287", 16)
    s = int("1aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e", 16)
    z = int("c2d48f45d7fbeff644ddb72b0f60df6c275f0943444d7df8cc851b3d55782669", 16)
    signature = r, s, z
    public_key = "042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabb"
    x = int(public_key[2:66], 16)
    y = int(public_key[66:], 16)
    public_key = x, y
    print("Verification: %s" % ecdsa.verify_signature(public_key, signature))
