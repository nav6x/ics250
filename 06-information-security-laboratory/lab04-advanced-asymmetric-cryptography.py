"""
Lab 04: Advanced Asymmetric Cryptography
ElGamal Cryptosystem (Encryption & Digital Signatures) and Elliptic Curve Cryptography (ECC).
"""

import hashlib

def mod_inverse(a, m):
    def egcd(a, b):
        if a == 0: return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m

class ElGamalSystem:
    def __init__(self, p=2357, g=2, x=175):
        self.p = p
        self.g = g
        self.x = x
        self.y = pow(g, x, p)

    def encrypt(self, m: int, k=107):
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(self.y, k, self.p)) % self.p
        return c1, c2

    def decrypt(self, c1: int, c2: int):
        s = pow(c1, self.x, self.p)
        s_inv = mod_inverse(s, self.p)
        return (c2 * s_inv) % self.p

    def sign(self, message: str, k=107):
        h_int = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (self.p - 1)
        r = pow(self.g, k, self.p)
        k_inv = mod_inverse(k, self.p - 1)
        s = ((h_int - self.x * r) * k_inv) % (self.p - 1)
        return r, s

    def verify(self, message: str, r: int, s: int):
        h_int = int(hashlib.sha256(message.encode()).hexdigest(), 16) % (self.p - 1)
        v1 = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p
        v2 = pow(self.g, h_int, self.p)
        return v1 == v2

if __name__ == "__main__":
    print("=== LAB 04: ADVANCED ASYMMETRIC CRYPTOGRAPHY (ELGAMAL) DEMO ===")
    elg = ElGamalSystem()
    msg_int = 42
    c1, c2 = elg.encrypt(msg_int)
    dec = elg.decrypt(c1, c2)
    print(f"ElGamal Encryption: Plaintext={msg_int} -> Cipher=(c1={c1}, c2={c2}) -> Decrypted={dec}")
    assert msg_int == dec, "ElGamal Decryption failed!"

    msg_str = "TRANSFER 1000 BTC"
    r, s = elg.sign(msg_str)
    valid = elg.verify(msg_str, r, s)
    print(f"ElGamal Signature : Msg='{msg_str}' -> Sig=(r={r}, s={s}) -> Verified={valid}")
    assert valid, "ElGamal Signature Verification failed!"
    print("[SUCCESS] All Lab 04 functions executed clean!")
