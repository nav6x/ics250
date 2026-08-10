"""
Lab 06: Digital Signatures & Public Key Infrastructure (PKI)
RSA Signatures (PKCS#1 v1.5) and Pure Python RSA Signature verification fallback.
"""

import hashlib

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

# Pure Python RSA Signature Fallback
def egcd(a, b):
    if a == 0: return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    return x % m

def pure_rsa_sign(message: str, d: int, n: int) -> int:
    h_int = int(hashlib.sha256(message.encode('utf-8')).hexdigest(), 16) % n
    return pow(h_int, d, n)

def pure_rsa_verify(message: str, signature_int: int, e: int, n: int) -> bool:
    h_int = int(hashlib.sha256(message.encode('utf-8')).hexdigest(), 16) % n
    h_decrypted = pow(signature_int, e, n)
    return h_int == h_decrypted

if __name__ == "__main__":
    print("=== LAB 06: DIGITAL SIGNATURES DEMO ===")
    msg = "AUTHORIZE WIRE TRANSFER TO ACCOUNT 987654321"

    if HAS_PYCRYPTODOME:
        key = RSA.generate(2048)
        h = SHA256.new(msg.encode('utf-8'))
        sig = pkcs1_15.new(key).sign(h)
        try:
            pkcs1_15.new(key.publickey()).verify(h, sig)
            valid = True
        except Exception:
            valid = False
        print(f"PyCryptodome RSA Signature (hex): {sig.hex()[:32]}... | Verified: {valid}")
    else:
        # Pure Python RSA
        p, q = 61, 53
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = modinv(e, phi)

        sig_int = pure_rsa_sign(msg, d, n)
        valid = pure_rsa_verify(msg, sig_int, e, n)
        print(f"Pure Python RSA Signature Int: {sig_int} | Verified: {valid}")
        assert valid, "Pure Python RSA Signature verification failed!"

    print("[SUCCESS] All Lab 06 functions executed clean!")
