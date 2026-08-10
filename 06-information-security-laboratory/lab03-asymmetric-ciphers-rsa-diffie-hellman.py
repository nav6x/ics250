"""
Lab 03: Asymmetric Key Ciphers
Extended Euclidean Algorithm, RSA Key Generation & Encryption, and Diffie-Hellman Key Exchange.
"""

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return x % m

def rsa_keygen(p=61, q=53):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return (e, n), (d, n)

def rsa_encrypt(msg_int: int, pub_key: tuple) -> int:
    e, n = pub_key
    return pow(msg_int, e, n)

def rsa_decrypt(cipher_int: int, priv_key: tuple) -> int:
    d, n = priv_key
    return pow(cipher_int, d, n)

def diffie_hellman_demo():
    p = 353
    g = 3
    a = 97   # Alice private key
    b = 233  # Bob private key

    A = pow(g, a, p)  # Alice public key
    B = pow(g, b, p)  # Bob public key

    K_alice = pow(B, a, p)  # Shared key computed by Alice
    K_bob = pow(A, b, p)    # Shared key computed by Bob

    return (p, g), (A, B), (K_alice, K_bob)

if __name__ == "__main__":
    print("=== LAB 03: ASYMMETRIC CIPHERS (RSA & DIFFIE-HELLMAN) DEMO ===")
    pub, priv = rsa_keygen()
    m = 1234
    c = rsa_encrypt(m, pub)
    dec = rsa_decrypt(c, priv)
    print(f"RSA Original  : {m}")
    print(f"RSA Ciphertext: {c}")
    print(f"RSA Decrypted : {dec}")
    assert m == dec, "RSA Decryption failed!"

    (p, g), (A, B), (Ka, Kb) = diffie_hellman_demo()
    print(f"\nDH Params: p={p}, g={g}")
    print(f"Alice Public A={A} | Bob Public B={B}")
    print(f"Alice Key={Ka} | Bob Key={Kb}")
    assert Ka == Kb, "Diffie-Hellman Key Exchange failed!"
    print("[SUCCESS] All Lab 03 functions executed clean!")
