"""
Lab 07: Partial Homomorphic Encryption
Multiplicative Homomorphic Property of RSA and Additive Homomorphic Property.
"""

def egcd(a, b):
    if a == 0: return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1: raise ValueError("No inverse")
    return x % m

def rsa_homomorphic_demo():
    p, q = 61, 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)

    # Multiplicative Homomorphic Property: Enc(m1) * Enc(m2) mod n == Enc(m1 * m2 mod n)
    m1 = 7
    m2 = 6

    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)

    c_prod = (c1 * c2) % n
    decrypted_prod = pow(c_prod, d, n)

    expected_prod = (m1 * m2) % n
    return (m1, m2), (c1, c2), decrypted_prod, expected_prod

if __name__ == "__main__":
    print("=== LAB 07: HOMOMORPHIC ENCRYPTION DEMO ===")
    (m1, m2), (c1, c2), dec_prod, exp_prod = rsa_homomorphic_demo()
    print(f"RSA Multiplicative Homomorphism: Enc({m1}) * Enc({m2}) mod n")
    print(f"Ciphertexts: c1={c1}, c2={c2}")
    print(f"Decrypted Product: {dec_prod} (Expected: {exp_prod})")
    assert dec_prod == exp_prod, "RSA Homomorphic multiplication failed!"
    print("[SUCCESS] All Lab 07 functions executed clean!")
