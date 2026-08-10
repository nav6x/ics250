# LAB 1: Basic Symmetric Key Ciphers

[← Back to Course README](../README.md)

- [Official ICAS Cyber Security Laboratory Manual & Record](#official-icas-cyber-security-laboratory-manual-record)

> **Topic**: LAB 1: Basic Symmetric Key Ciphers: Official ICAS Cyber Security Laboratory Manual & Record, ---------- Helper Functions ----------, Modular inverse exists only if gcd(a, m) = 1, Remove spaces and normalize to lowercase

---

## Official ICAS Cyber Security Laboratory Manual & Record

```markdown
Lab Exercises
1.
Encrypt the message "I am learning information security" using each of the following 
ciphers. Ignore the space between words. Decrypt the message to get the original 
plaintext:
–
a) Additive cipher with key = 20
–
b) Multiplicative cipher with key = 15
–
c) Affine cipher with key = (15, 20)
# ---------- Helper Functions ----------
def mod_inverse(a, m):
    # Modular inverse exists only if gcd(a, m) = 1
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None
def format_text(text):
    # Remove spaces and normalize to lowercase
    return text.replace(" ", "").lower()
# ---------- Additive Cipher ----------
def additive_cipher(text, key, mode='encrypt'):
    result = ""
    shift = key if mode == 'encrypt' else -key
    
    for char in text:
        base = ord('a')
        result += chr((ord(char) - base + shift) % 26 + base)
        
    return result
# ---------- Multiplicative Cipher ----------
def multiplicative_cipher(text, key, mode='encrypt'):
    result = ""
    
    if mode == 'encrypt':
        factor = key
    else:
        # Decryption requires modular inverse of key
        factor = mod_inverse(key, 26)
        if factor is None:
            raise ValueError("Key has no modular inverse (not coprime 
with 26)")


    
    for char in text:
        base = ord('a')
        result += chr(((ord(char) - base) * factor) % 26 + base)
        
    return result
# ---------- Affine Cipher ----------
def affine_cipher(text, a, b, mode='encrypt'):
    result = ""
    
    if mode == 'decrypt':
        inv_a = mod_inverse(a, 26)
        if inv_a is None:
            raise ValueError("Key 'a' has no modular inverse")
    
    for char in text:
        base = ord('a')
        x = ord(char) - base
        
        if mode == 'encrypt':
            # E(x) = (ax + b) mod 26
            result += chr((a * x + b) % 26 + base)
        else:
            # D(x) = a^-1 (x - b) mod 26
            result += chr((inv_a * (x - b)) % 26 + base)
            
    return result
# ---------- Main Execution ----------
plaintext = format_text("I am learning information security")
print("Original:", plaintext)
print()
# Additive Cipher
add_enc = additive_cipher(plaintext, 20, 'encrypt')
add_dec = additive_cipher(add_enc, 20, 'decrypt')
print("Additive Cipher:")
print("Encrypted:", add_enc)
print("Decrypted:", add_dec)
print()
# Multiplicative Cipher
mul_enc = multiplicative_cipher(plaintext, 15, 'encrypt')
mul_dec = multiplicative_cipher(mul_enc, 15, 'decrypt')


print("Multiplicative Cipher:")
print("Encrypted:", mul_enc)
print("Decrypted:", mul_dec)
print()
# Affine Cipher
aff_enc = affine_cipher(plaintext, 15, 20, 'encrypt')
aff_dec = affine_cipher(aff_enc, 15, 20, 'decrypt')
print("Affine Cipher:")
print("Encrypted:", aff_enc)
print("Decrypted:", aff_dec)
Original: iamlearninginformationsecurity
Additive Cipher:
Encrypted: cugfyulhchachzilguncihmywolcns
Decrypted: iamlearninginformationsecurity
Multiplicative Cipher:
Encrypted: qayjiavnqnmqnxcvyazqcnkieovqzw
Decrypted: iamlearninginformationsecurity
Affine Cipher:
Encrypted: kusdcuphkhgkhrwpsutkwhecyipktq
Decrypted: iamlearninginformationsecurity
1.
Encrypt the message "the house is being sold tonight" using each of the following 
ciphers. Ignore the space between words. Decrypt the message to get the original 
plaintext:
–
a) Vigenere cipher with key: "dollars"
–
b) Autokey cipher with key = 7
# ---------- Helper Function ----------
def format_text(text):
    return text.replace(" ", "").lower()
# ---------- Vigenère Cipher ----------
def vigenere_cipher(text, key, mode='encrypt'):
    text = format_text(text)
    key = key.lower()
    result = ""
    
    for i, char in enumerate(text):
        shift = ord(key[i % len(key)]) - ord('a')
        
        if mode == 'decrypt':
            shift = -shift


        
        # Each letter is shifted using repeating key
        result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
    
    return result
# ---------- Autokey Cipher ----------
def autokey_cipher(text, initial_key, mode='encrypt'):
    text = format_text(text)
    result = ""
    
    if mode == 'encrypt':
        # Key stream = initial key + plaintext values
        key_stream = [initial_key] + [ord(c) - ord('a') for c in 
text[:-1]]
        
        for i, char in enumerate(text):
            shift = key_stream[i]
            result += chr((ord(char) - ord('a') + shift) % 26 + 
ord('a'))
    
    elif mode == 'decrypt':
        key_stream = [initial_key]
        
        for i, char in enumerate(text):
            shift = key_stream[i]
            
            # Recover plaintext first
            plain_val = (ord(char) - ord('a') - shift) % 26
            result_char = chr(plain_val + ord('a'))
            result += result_char
            
            # Then extend key stream using recovered plaintext
            key_stream.append(plain_val)
    
    return result
# ---------- Main Execution ----------
plaintext = "the house is being sold tonight"
print("Original:", format_text(plaintext))
print()
# Vigenère Cipher
vig_enc = vigenere_cipher(plaintext, "dollars", "encrypt")
vig_dec = vigenere_cipher(vig_enc, "dollars", "decrypt")


print("Vigenère Cipher:")
print("Encrypted:", vig_enc)
print("Decrypted:", vig_dec)
print()
# Autokey Cipher
auto_enc = autokey_cipher(plaintext, 7, "encrypt")
auto_dec = autokey_cipher(auto_enc, 7, "decrypt")
print("Autokey Cipher:")
print("Encrypted:", auto_enc)
print("Decrypted:", auto_dec)
Original: thehouseisbeingsoldtonight
Vigenère Cipher:
Encrypted: wvpsolkhwdmezfjgzwdkgqwrst
Decrypted: thehouseisbeingsoldtonight
Autokey Cipher:
Encrypted: aallvimwmatfmvtygzowhbvona
Decrypted: thehouseisbeingsoldtonight
1.
Use the Playfair cipher to encipher the message "The key is hidden under the door pad". 
The secret key can be made by filling the first and part of the second row with the word 
"GUIDANCE" and filling the rest of the matrix with the rest of the alphabet.
# ---------- Create Playfair Matrix ----------
def create_playfair_matrix(key):
    # Playfair uses 25 letters (I/J combined)
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = key.upper().replace("J", "I")
    
    seen = set()
    matrix_list = []
    
    # Insert key characters first
    for char in key:
        if char.isalpha() and char not in seen:
            matrix_list.append(char)
            seen.add(char)
    
    # Fill remaining alphabet
    for char in alphabet:
        if char not in seen:
            matrix_list.append(char)
    
    # Convert to 5x5 matrix
    return [matrix_list[i:i+5] for i in range(0, 25, 5)]


# ---------- Format Plaintext ----------
def format_text(text):
    text = text.upper().replace(" ", "").replace("J", "I")
    result = ""
    i = 0
    
    while i < len(text):
        result += text[i]
        
        if i + 1 < len(text):
            if text[i] == text[i+1]:
                # Insert filler to break repeated letters
                result += 'X'
            else:
                result += text[i+1]
                i += 1
        i += 1
    
    # Ensure even length
    if len(result) % 2 != 0:
        result += 'X'
    
    return result
# ---------- Find Position ----------
def find_position(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
# ---------- Playfair Encryption ----------
def playfair_encrypt(text, key):
    matrix = create_playfair_matrix(key)
    text = format_text(text)
    
    result = ""
    
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)
        
        if r1 == r2:
            # Same row → shift right
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]


        
        elif c1 == c2:
            # Same column → shift down
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]
        
        else:
            # Rectangle swap columns
            result += matrix[r1][c2]
            result += matrix[r2][c1]
    
    return result, matrix, text
# ---------- Main Execution ----------
plaintext = "The key is hidden under the door pad"
key = "GUIDANCE"
ciphertext, matrix, formatted_text = playfair_encrypt(plaintext, key)
print("Playfair Matrix:")
for row in matrix:
    print(" ".join(row))
print("\nFormatted Plaintext:", formatted_text)
print("Encrypted Ciphertext:", ciphertext)
Playfair Matrix:
G U I D A
N C E B F
H K L M O
P Q R S T
V W X Y Z
Formatted Plaintext: THEKEYISHIDXDENUNDERTHEDOXORPADX
Encrypted Ciphertext: POCLBXDRLGIYIBCGBGLXPOBILZLTTGIY
1.
Use a Hill cipher to encipher the message "We live in an insecure world". Use the 
following key: K = [03 03 02 07]
import numpy as np
# ---------- Helper Functions ----------
def char_to_num(c):
    return ord(c) - ord('a')
def num_to_char(n):
    return chr(n + ord('a'))


def format_text(text):
    return text.replace(" ", "").lower()
# ---------- Modular Inverse of Matrix ----------
def mod_inverse_matrix(matrix, mod):
    # Determinant for 2x2 matrix
    det = int(np.round(np.linalg.det(matrix)))
    
    # Find inverse of determinant mod 26
    det_inv = None
    for i in range(1, mod):
        if (det * i) % mod == 1:
            det_inv = i
            break
    
    if det_inv is None:
        raise ValueError("Matrix not invertible in mod 26")
    
    # Adjugate of 2x2 matrix
    adj = np.array([
        [matrix[1][1], -matrix[0][1]],
        [-matrix[1][0], matrix[0][0]]
    ])
    
    # K⁻¹ = det⁻¹ × adj(K) mod 26
    return (det_inv * adj) % mod
# ---------- Hill Cipher ----------
def hill_cipher(text, key_matrix, mode='encrypt'):
    text = format_text(text)
    
    # Padding ensures vector size compatibility
    if len(text) % 2 != 0:
        text += 'x'
    
    result = ""
    K = np.array(key_matrix)
    
    if mode == 'decrypt':
        K = mod_inverse_matrix(K, 26)
    
    for i in range(0, len(text), 2):
        vector = np.array([
            char_to_num(text[i]),
            char_to_num(text[i+1])
        ])
        
        # Matrix multiplication in mod 26 space


        transformed = np.dot(K, vector) % 26
        
        result += num_to_char(int(transformed[0]))
        result += num_to_char(int(transformed[1]))
    
    return result
# ---------- Main Execution ----------
plaintext = "We live in an insecure world"
key_matrix = [[3, 3], [2, 7]]
formatted = format_text(plaintext)
ciphertext = hill_cipher(plaintext, key_matrix, 'encrypt')
decrypted = hill_cipher(ciphertext, key_matrix, 'decrypt')
print("Original:", formatted)
print("Encrypted:", ciphertext)
print("Decrypted:", decrypted)
Original: weliveinaninsecureworld
Encrypted: aufaxsldnnldomoolkemghal
Decrypted: weliveinaninsecureworldx
1.
John is reading a mystery book involving cryptography. In one part of the book, the 
author gives a ciphertext "CIW" and two paragraphs later the author tells the reader that 
this is a shift cipher and the plaintext is "yes". In the next chapter, the hero found a tablet 
in a cave with "XVIEWYWI" engraved on it. John immediately found the actual meaning 
of the ciphertext. Identify the type of attack and plaintext.
# ---------- Helper Function ----------
def char_to_num(c):
    return ord(c) - ord('A')
def num_to_char(n):
    return chr(n + ord('A'))
# ---------- Find Shift Key ----------
def find_shift(cipher, plain):
    # Using first character pair to compute shift
    c = char_to_num(cipher[0])
    p = char_to_num(plain[0])
    
    # Shift = (P - C) mod 26
    return (p - c) % 26
# ---------- Decrypt Using Shift ----------


def shift_decrypt(text, shift):
    result = ""
    
    for char in text:
        x = char_to_num(char)
        result += num_to_char((x + shift) % 26)
    
    return result
# ---------- Main Execution ----------
known_cipher = "CIW"
known_plain = "YES"
# Step 1: Recover key
shift_key = find_shift(known_cipher, known_plain)
# Step 2: Decrypt new ciphertext
ciphertext = "XVIEWYWI"
plaintext = shift_decrypt(ciphertext, shift_key)
print("Known Ciphertext:", known_cipher)
print("Known Plaintext:", known_plain)
print("Recovered Shift Key:", shift_key)
print()
print("New Ciphertext:", ciphertext)
print("Decrypted Plaintext:", plaintext)
Known Ciphertext: CIW
Known Plaintext: YES
Recovered Shift Key: 22
New Ciphertext: XVIEWYWI
Decrypted Plaintext: TREASUSE
1.
Use a brute-force attack to decipher the following message. Assume that you know it is 
an affine cipher and that the plaintext "ab" is enciphered to "GL": 
XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS
# ---------- Helper Functions ----------
def mod_inverse(a, m):
    # Required to reverse multiplication in mod arithmetic
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None
def char_to_num(c):


    return ord(c) - ord('A')
def num_to_char(n):
    return chr(n + ord('A'))
# ---------- Affine Decryption ----------
def affine_decrypt(ciphertext, a, b):
    result = ""
    
    inv_a = mod_inverse(a, 26)
    if inv_a is None:
        raise ValueError("Invalid key: no modular inverse for 'a'")
    
    for char in ciphertext:
        x = char_to_num(char)
        
        # P = a^-1 (C - b) mod 26
        p = (inv_a * (x - b)) % 26
        result += num_to_char(p)
    
    return result
# ---------- Main Execution ----------
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
# Derived from known plaintext attack
a = 5
b = 6
plaintext = affine_decrypt(ciphertext, a, b)
print("Ciphertext:", ciphertext)
print("Derived Keys: a =", a, ", b =", b)
print("Decrypted Plaintext:", plaintext)
Ciphertext: XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS
Derived Keys: a = 5 , b = 6
Decrypted Plaintext: THEBESTOFAFIGHTISMAKINGUPAKTERWARDS
Additional Exercises
1.
Use a brute-force attack to decipher the following message enciphered by Alice using an 
additive cipher. Suppose that Alice always uses a key that is close to her birthday, which 
is on the 13th of the month: 
NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY
# ---------- Helper Functions ----------


def char_to_num(c):
    return ord(c) - ord('A')
def num_to_char(n):
    return chr(n + ord('A'))
# ---------- Additive Cipher Decryption ----------
def additive_decrypt(text, key):
    result = ""
    
    for char in text:
        if char.isalpha():
            x = char_to_num(char)
            # Reverse shift
            result += num_to_char((x - key) % 26)
        else:
            # Preserve symbols like / & etc.
            result += char
    
    return result
# ---------- Main Execution ----------
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"
print("Trying keys near 13 (10 to 16):\n")
for key in range(10, 17):
    decrypted = additive_decrypt(ciphertext, key)
    print(f"Key {key}: {decrypted}")
Trying keys near 13 (10 to 16):
Key 10: DSZQUPHSBQI/BOETUFHBOPHSBQIZBSFUXPTJEFTPEBD&RO
Key 11: CRYPTOGRAPH/ANDSTEGANOGRAPHYARETWOSIDESODAC&QN
Key 12: BQXOSNFQZOG/ZMCRSDFZMNFQZOGXZQDSVNRHCDRNCZB&PM
Key 13: APWNRMEPYNF/YLBQRCEYLMEPYNFWYPCRUMQGBCQMBYA&OL
Key 14: ZOVMQLDOXME/XKAPQBDXKLDOXMEVXOBQTLPFABPLAXZ&NK
Key 15: YNULPKCNWLD/WJZOPACWJKCNWLDUWNAPSKOEZAOKZWY&MJ
Key 16: XMTKOJBMVKC/VIYNOZBVIJBMVKCTVMZORJNDYZNJYVX&LI
1.
Eve secretly gets access to Alice's computer and using her cipher types "abcdefghi". The 
screen shows "CABDEHFGL". If Eve knows that Alice is using a keyed transposition 
cipher, answer the following questions:
–
a) What type of attack is Eve launching?
–
b) What is the size of the permutation key?
–
c) Use the Vigenere cipher with keyword "HEALTH" to encipher the message "Life 
is full of surprises".


# ---------- Helper Function ----------
def vigenere_cipher(text, key):
    result = ""
    key = key.lower()
    key_index = 0
    
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            
            base = ord('A') if is_upper else ord('a')
            
            # Shift based on key character
            shift = ord(key[key_index % len(key)]) - ord('a')
            
            encrypted_char = chr((ord(char) - base + shift) % 26 + 
base)
            result += encrypted_char
            
            key_index += 1
        else:
            # Preserve spaces
            result += char
    
    return result
# ---------- Main Execution ----------
plaintext = "Life is full of surprises"
key = "HEALTH"
ciphertext = vigenere_cipher(plaintext, key)
print("Plaintext:", plaintext)
print("Key:", key)
print("Encrypted Ciphertext:", ciphertext)
Plaintext: Life is full of surprises
Key: HEALTH
Encrypted Ciphertext: Smfp bz mylw hm zyrakpzis
```
