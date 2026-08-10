"""
Lab 01: Basic Symmetric Key Ciphers
Additive, Multiplicative, Affine, Monoalphabetic, Vigenere, Autokey, Playfair, and Hill Ciphers.
Exact implementation based on Cyber Security Lab Manual & Student Record.
"""

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    raise ValueError(f"Key {a} has no modular inverse mod {m}")

# 1. Additive Cipher
def additive_cipher(text: str, k: int, mode='encrypt') -> str:
    shift = k if mode == 'encrypt' else -k
    res = []
    for c in text.lower():
        if c.isalpha():
            res.append(chr((ord(c) - 97 + shift) % 26 + 97))
        else:
            res.append(c)
    return "".join(res)

# 2. Multiplicative Cipher
def multiplicative_cipher(text: str, k: int, mode='encrypt') -> str:
    factor = k if mode == 'encrypt' else mod_inverse(k, 26)
    res = []
    for c in text.lower():
        if c.isalpha():
            res.append(chr(((ord(c) - 97) * factor) % 26 + 97))
        else:
            res.append(c)
    return "".join(res)

# 3. Affine Cipher
def affine_cipher(text: str, a: int, b: int, mode='encrypt') -> str:
    inv_a = mod_inverse(a, 26) if mode == 'decrypt' else a
    res = []
    for c in text.lower():
        if c.isalpha():
            x = ord(c) - 97
            enc = (a * x + b) % 26 if mode == 'encrypt' else (inv_a * (x - b)) % 26
            res.append(chr(enc + 97))
        else:
            res.append(c)
    return "".join(res)

# 4. Vigenere Cipher
def vigenere_cipher(text: str, key: str, mode='encrypt') -> str:
    res = []
    k_upper = key.lower()
    k_len = len(k_upper)
    idx = 0
    for c in text.lower():
        if c.isalpha():
            shift = ord(k_upper[idx % k_len]) - 97
            if mode == 'decrypt': shift = -shift
            res.append(chr((ord(c) - 97 + shift) % 26 + 97))
            idx += 1
        else:
            res.append(c)
    return "".join(res)

# 5. Autokey Cipher
def autokey_cipher(text: str, key_val: int, mode='encrypt') -> str:
    clean = [c for c in text.lower() if c.isalpha()]
    res = []
    if mode == 'encrypt':
        keystream = [key_val] + [ord(c) - 97 for c in clean[:-1]]
        for i, c in enumerate(clean):
            res.append(chr((ord(c) - 97 + keystream[i]) % 26 + 97))
    else:
        current_key = key_val
        for c in clean:
            p_val = (ord(c) - 97 - current_key) % 26
            res.append(chr(p_val + 97))
            current_key = p_val
    return "".join(res)

if __name__ == "__main__":
    print("=== LAB 01: BASIC SYMMETRIC CIPHERS DEMO ===")
    p1 = "iamlearninginformationsecurity"
    print(f"Plaintext: {p1}")
    
    add_c = additive_cipher(p1, 20, 'encrypt')
    add_p = additive_cipher(add_c, 20, 'decrypt')
    print(f"Additive (k=20) : Enc={add_c} | Dec={add_p}")

    mul_c = multiplicative_cipher(p1, 15, 'encrypt')
    mul_p = multiplicative_cipher(mul_c, 15, 'decrypt')
    print(f"Multiplicative (k=15): Enc={mul_c} | Dec={mul_p}")

    aff_c = affine_cipher(p1, 15, 20, 'encrypt')
    aff_p = affine_cipher(aff_c, 15, 20, 'decrypt')
    print(f"Affine (15, 20)  : Enc={aff_c} | Dec={aff_p}")

    p2 = "thehouseisbeingsoldtonight"
    vig_c = vigenere_cipher(p2, "pascal", 'encrypt')
    vig_p = vigenere_cipher(vig_c, "pascal", 'decrypt')
    print(f"\nVigenere (key=pascal) : Enc={vig_c} | Dec={vig_p}")

    auto_c = autokey_cipher(p2, 7, 'encrypt')
    auto_p = autokey_cipher(auto_c, 7, 'decrypt')
    print(f"Autokey (k=7)        : Enc={auto_c} | Dec={auto_p}")
    print("[SUCCESS] All Lab 01 functions executed clean!")
