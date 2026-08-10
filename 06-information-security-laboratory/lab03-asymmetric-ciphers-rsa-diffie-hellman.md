# LAB 3: Asymmetric Key Ciphers

[← Back to Course README](../README.md)

- [Official ICAS Cyber Security Laboratory Manual & Record](#official-icas-cyber-security-laboratory-manual-record)
> **Topic**: LAB 3: Asymmetric Key Ciphers: Official ICAS Cyber Security Laboratory Manual & Record, ---------- Imports ----------, ---------- Main Execution ----------, ---------- Key Generation ----------

---

## Official ICAS Cyber Security Laboratory Manual & Record

```markdown
Lab Exercises
1.
Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n, e). Then 
decrypt the ciphertext with the private key (n, d) to verify the original message.
# ---------- Imports ----------
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
# ---------- Main Execution ----------
message = b"Asymmetric Encryption"
# ---------- Key Generation ----------
# 2048-bit RSA (standard secure size)
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()
# ---------- Encryption ----------
cipher_encrypt = PKCS1_OAEP.new(public_key)
ciphertext = cipher_encrypt.encrypt(message)


# ---------- Decryption ----------
cipher_decrypt = PKCS1_OAEP.new(private_key)
decrypted_message = cipher_decrypt.decrypt(ciphertext)
# ---------- Output ----------
print("Original Message:", message.decode())
print("Ciphertext (hex):", ciphertext.hex()[:60], "...")  # truncated 
for readability
print("Decrypted Message:", decrypted_message.decode())
Original Message: Asymmetric Encryption
Ciphertext (hex): 
f3570d331e1d569b682f52b6ac7935492fd9a90a13c5def6e7d6ade6057c ...
Decrypted Message: Asymmetric Encryption
1.
Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure Transactions" 
with the public key. Then decrypt the ciphertext with the private key to verify the original 
message.
# ---------- Imports ----------
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, 
modes
# ---------- Helper Functions ----------
def derive_key(shared_secret):
    # Converts shared secret into usable AES key
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
def ecc_encrypt(public_key, message):
    # Generate ephemeral key pair (fresh for each encryption)
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key()
    
    # Shared secret using ECDH
    shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)
    


    aes_key = derive_key(shared_secret)
    
    # GCM mode gives confidentiality + integrity
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv)
    ).encryptor()
    
    ciphertext = encryptor.update(message) + encryptor.finalize()
    
    return ephemeral_public, iv, ciphertext, encryptor.tag
def ecc_decrypt(private_key, ephemeral_public, iv, ciphertext, tag):
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
    
    aes_key = derive_key(shared_secret)
    
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag)
    ).decryptor()
    
    return decryptor.update(ciphertext) + decryptor.finalize()
# ---------- Main Execution ----------
message = b"Secure Transactions"
# Receiver generates key pair
receiver_private = ec.generate_private_key(ec.SECP256R1())
receiver_public = receiver_private.public_key()
# ---------- Encryption ----------
ephemeral_pub, iv, ciphertext, tag = ecc_encrypt(receiver_public, 
message)
# ---------- Decryption ----------
decrypted = ecc_decrypt(receiver_private, ephemeral_pub, iv, 
ciphertext, tag)
# ---------- Output ----------
print("Original Message:", message.decode())
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted Message:", decrypted.decode())


Original Message: Secure Transactions
Ciphertext (hex): e38b3c6f3f9c706f4b147313edf90a2828ecad
Decrypted Message: Secure Transactions
1.
Given an ElGamal encryption scheme with a public key (p, g, h) and a private key x, 
encrypt the message "Confidential Data". Then decrypt the ciphertext to retrieve the 
original message.
# ---------- Imports ----------
import random
from Crypto.Util.number import getPrime
# ---------- Helper Function ----------
def mod_exp(base, exp, mod):
    # Fast modular exponentiation (core of ElGamal)
    return pow(base, exp, mod)
# ---------- Main Execution ----------
message = "Confidential Data"
# Generate a small prime (for lab simplicity)
p = getPrime(16)
g = 2  # generator
# Private key
x = random.randint(1, p - 2)
# Public key component
h = mod_exp(g, x, p)
print("Public Key (p, g, h):", (p, g, h))
print("Private Key x:", x)
# ---------- Encryption ----------
ciphertext = []
for char in message:
    m = ord(char)
    
    # Random session key (different each time → probabilistic 
encryption)
    k = random.randint(1, p - 2)
    
    c1 = mod_exp(g, k, p)
    c2 = (m * mod_exp(h, k, p)) % p
    


    ciphertext.append((c1, c2))
print("\nCiphertext (first few pairs):", ciphertext[:3], "...")
# ---------- Decryption ----------
decrypted = ""
for c1, c2 in ciphertext:
    s = mod_exp(c1, x, p)
    
    # Fermat's Little Theorem for inverse:
    # s^-1 ≡ s^(p-2) mod p
    s_inv = mod_exp(s, p - 2, p)
    
    m = (c2 * s_inv) % p
    decrypted += chr(m)
print("\nDecrypted Message:", decrypted)
Public Key (p, g, h): (61331, 2, 36670)
Private Key x: 48247
Ciphertext (first few pairs): [(58732, 36459), (5784, 23635), (14150, 
30918)] ...
Decrypted Message: Confidential Data
1.
Design and implement a secure file transfer system using RSA (2048-bit) and ECC 
(secp256r1 curve) public key algorithms. Generate and exchange keys, then encrypt and 
decrypt files of varying sizes (e.g., 1 MB, 10 MB) using both algorithms. Measure and 
compare the performance in terms of key generation time, encryption/decryption speed, 
and computational overhead. Evaluate the security and efficiency of each algorithm in 
the context of file transfer, considering factors such as key size, storage requirements, 
and resistance to known attacks. Document your findings, including performance metrics 
and a summary of the strengths and weaknesses of RSA and ECC for secure file transfer.
# ---------- Imports ----------
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
# ---------- Helper: Derive AES Key from ECC ----------
def derive_key(shared_secret):


    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file-transfer'
    ).derive(shared_secret)
# ---------- Main Execution ----------
# Simulated "file"
file_data = b"This is a confidential file content."
print("Original File Data:", file_data.decode())
# =====================================================
# STEP 1: Generate RSA Keys (for secure key transport)
# =====================================================
rsa_key = RSA.generate(2048)
rsa_private = rsa_key
rsa_public = rsa_key.publickey()
# =====================================================
# STEP 2: Generate ECC Keys (for shared secret)
# =====================================================
receiver_private_ecc = ec.generate_private_key(ec.SECP256R1())
receiver_public_ecc = receiver_private_ecc.public_key()
sender_private_ecc = ec.generate_private_key(ec.SECP256R1())
sender_public_ecc = sender_private_ecc.public_key()
# Shared secret (ECDH)
shared_secret_sender = sender_private_ecc.exchange(ec.ECDH(), 
receiver_public_ecc)
shared_secret_receiver = receiver_private_ecc.exchange(ec.ECDH(), 
sender_public_ecc)
# Derive AES key from shared secret
aes_key = derive_key(shared_secret_sender)
# =====================================================
# STEP 3: Encrypt File using AES
# =====================================================
iv = os.urandom(16)
aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
ciphertext = aes_cipher.encrypt(pad(file_data, AES.block_size))


# =====================================================
# STEP 4: Encrypt AES Key using RSA
# =====================================================
rsa_cipher = PKCS1_OAEP.new(rsa_public)
encrypted_aes_key = rsa_cipher.encrypt(aes_key)
# =====================================================
# STEP 5: Receiver Side
# =====================================================
# Recover AES key using RSA private key
rsa_dec = PKCS1_OAEP.new(rsa_private)
recovered_aes_key = rsa_dec.decrypt(encrypted_aes_key)
# Decrypt file using AES
aes_dec = AES.new(recovered_aes_key, AES.MODE_CBC, iv)
decrypted_file = unpad(aes_dec.decrypt(ciphertext), AES.block_size)
# ---------- Output ----------
print("\nEncrypted File (hex):", ciphertext.hex())
print("\nDecrypted File Data:", decrypted_file.decode())
Original File Data: This is a confidential file content.
Encrypted File (hex): 
7d274b94336a8224b9f0940a62d17c8fd779d0a745652853894bb70f6ef2e16399b1ca
f437971f3e01edd374902c7b93
Decrypted File Data: This is a confidential file content.
1.
As part of a project to enhance the security of communication in a peer-to-peer file 
sharing system, you are tasked with implementing a secure key exchange mechanism 
using the Diffie-Hellman algorithm. Each peer must establish a shared secret key with 
another peer over an insecure channel. Implement the Diffie-Hellman key exchange 
protocol, enabling peers to generate their public and private keys and securely compute 
the shared secret key. Measure the time taken for key generation and key exchange 
processes.
# ---------- Imports ----------
import random
import time
from Crypto.Util.number import getPrime
# ---------- Helper Function ----------
def mod_exp(base, exp, mod):
    # Efficient modular exponentiation
    return pow(base, exp, mod)


# ---------- Main Execution ----------
# Generate large prime (for lab simplicity using 128 bits)
start_keygen = time.perf_counter()
p = getPrime(128)
g = 2  # common generator
# Alice's private & public keys
a = random.randint(1, p - 2)
A = mod_exp(g, a, p)
# Bob's private & public keys
b = random.randint(1, p - 2)
B = mod_exp(g, b, p)
end_keygen = time.perf_counter()
# ---------- Key Exchange ----------
start_exchange = time.perf_counter()
# Alice computes shared secret
shared_secret_alice = mod_exp(B, a, p)
# Bob computes shared secret
shared_secret_bob = mod_exp(A, b, p)
end_exchange = time.perf_counter()
# ---------- Output ----------
print("Public Parameters:")
print("p =", p)
print("g =", g)
print("\nAlice Public Key (A):", A)
print("Bob Public Key (B):", B)
print("\nShared Secret (Alice):", shared_secret_alice)
print("Shared Secret (Bob):", shared_secret_bob)
# Verify both match
print("\nKeys Match:", shared_secret_alice == shared_secret_bob)
# ---------- Timing ----------
keygen_time = (end_keygen - start_keygen) * 1000
exchange_time = (end_exchange - start_exchange) * 1000


print("\nTime Taken:")
print(f"Key Generation Time: {keygen_time:.4f} ms")
print(f"Key Exchange Time: {exchange_time:.4f} ms")
Public Parameters:
p = 329927620613858270238036150118596594899
g = 2
Alice Public Key (A): 179110005375630641662175495545566770447
Bob Public Key (B): 53772352688783683183171583631019522267
Shared Secret (Alice): 33524199773836128651831797224617776870
Shared Secret (Bob): 33524199773836128651831797224617776870
Keys Match: True
Time Taken:
Key Generation Time: 49.6338 ms
Key Exchange Time: 1.6038 ms
Additional Exercises
1.
With the ElGamal public key (p = 7919, g = 2, h = 6465) and the private key x = 2999, 
encrypt the message "Asymmetric Algorithms". Decrypt the resulting ciphertext to verify 
the original message.
# ---------- Helper Function ----------
def mod_exp(base, exp, mod):
    return pow(base, exp, mod)
# ---------- Main Execution ----------
# Given values
p = 7919
g = 2
h = 6465
x = 2999
message = "Asymmetric Algorithms"
# Fixed k (for reproducibility in lab)
k = 1500
# ---------- Encryption ----------
ciphertext = []
for char in message:
    m = ord(char)
    


    c1 = mod_exp(g, k, p)
    c2 = (m * mod_exp(h, k, p)) % p
    
    ciphertext.append((c1, c2))
print("Ciphertext (first few):", ciphertext[:4], "...")
# ---------- Decryption ----------
decrypted = ""
for c1, c2 in ciphertext:
    s = mod_exp(c1, x, p)
    
    # Modular inverse using Fermat
    s_inv = mod_exp(s, p - 2, p)
    
    m = (c2 * s_inv) % p
    decrypted += chr(m)
print("Decrypted Message:", decrypted)
Ciphertext (first few): [(3618, 6848), (3618, 5415), (3618, 3976), 
(3618, 6854)] ...
Decrypted Message: ᒖ૒ຟZ᧙ᡣᙦ܅ᒖ
1.
Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure Transactions" 
with the public key. Then decrypt the ciphertext with the private key to verify the original 
message.
# ---------- Imports ----------
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, 
modes
# ---------- Helper Functions ----------
def derive_key(shared_secret):
    # Derive AES key from shared secret
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc-encryption'
    ).derive(shared_secret)


def ecc_encrypt(public_key, message):
    # Ephemeral key pair ensures forward secrecy
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key()
    
    shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)
    aes_key = derive_key(shared_secret)
    
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv)
    ).encryptor()
    
    ciphertext = encryptor.update(message) + encryptor.finalize()
    
    return ephemeral_public, iv, ciphertext, encryptor.tag
def ecc_decrypt(private_key, ephemeral_public, iv, ciphertext, tag):
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
    aes_key = derive_key(shared_secret)
    
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag)
    ).decryptor()
    
    return decryptor.update(ciphertext) + decryptor.finalize()
# ---------- Main Execution ----------
message = b"Secure Transactions"
# Receiver key pair
receiver_private = ec.generate_private_key(ec.SECP256R1())
receiver_public = receiver_private.public_key()
# ---------- Encryption ----------
eph_pub, iv, ciphertext, tag = ecc_encrypt(receiver_public, message)
# ---------- Decryption ----------
decrypted = ecc_decrypt(receiver_private, eph_pub, iv, ciphertext, 
tag)


# ---------- Output ----------
print("Original Message:", message.decode())
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted Message:", decrypted.decode())
Original Message: Secure Transactions
Ciphertext (hex): c0ce7a8e30bf201613b923a0429295ad10ebfc
Decrypted Message: Secure Transactions
1.
Encrypt the message "Cryptographic Protocols" using the RSA public key (n, e) where n = 
323 and e = 5. Decrypt the ciphertext with the private key (n, d) where d = 173 to confirm 
the original message.
# ---------- Main Execution ----------
# Given RSA parameters
n = 323
e = 5
d = 173
message = "Cryptographic Protocols"
# ---------- Encryption ----------
# Each character → integer → RSA operation
ciphertext = [pow(ord(char), e, n) for char in message]
print("Ciphertext (first few values):", ciphertext[:5], "...")
# ---------- Decryption ----------
# Reverse RSA operation
decrypted = "".join([chr(pow(c, d, n)) for c in ciphertext])
print("Decrypted Message:", decrypted)
Ciphertext (first few values): [288, 190, 49, 6, 165] ...
Decrypted Message: Cryptographic Protocols
1.
You are tasked with implementing a secure communication system for a healthcare 
organization to exchange sensitive patient information securely between doctors and 
hospitals. Implement the ElGamal encryption scheme to encrypt patient records and 
medical data, ensuring confidentiality during transmission. Generate public and private 
keys using the secp256r1 curve and use ElGamal encryption to encrypt patient data with 
the recipient's public key and decrypt it with the recipient's private key. Measure the 
performance of encryption and decryption processes for data of varying sizes.
# ---------- Imports ----------
import os
import time
from cryptography.hazmat.primitives.asymmetric import ec


from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, 
modes
# ---------- Helper Functions ----------
def derive_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'healthcare-system'
    ).derive(shared_secret)
def ecc_encrypt(public_key, data):
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key()
    
    shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)
    aes_key = derive_key(shared_secret)
    
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv)
    ).encryptor()
    
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    return ephemeral_public, iv, ciphertext, encryptor.tag
def ecc_decrypt(private_key, ephemeral_public, iv, ciphertext, tag):
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
    aes_key = derive_key(shared_secret)
    
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag)
    ).decryptor()
    
    return decryptor.update(ciphertext) + decryptor.finalize()
# ---------- Main Execution ----------
# ECC Key pair (doctor)


private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
# Sample patient data
records = {
    "Short Record": b"Patient: John Doe, Status: Healthy",
    "Medium Record": os.urandom(500),
    "Large Record": os.urandom(5 * 1024)
}
# ---------- Processing ----------
for record_type, data in records.items():
    print(f"\nProcessing {record_type} (Size: {len(data)} bytes)")
    
    # Encryption timing
    start_enc = time.perf_counter()
    eph_pub, iv, ciphertext, tag = ecc_encrypt(public_key, data)
    enc_time = time.perf_counter() - start_enc
    
    # Decryption timing
    start_dec = time.perf_counter()
    decrypted = ecc_decrypt(private_key, eph_pub, iv, ciphertext, tag)
    dec_time = time.perf_counter() - start_dec
    
    # Verify correctness
    print("Decryption Correct:", decrypted == data)
    print(f"Encryption Time: {enc_time:.6f} sec")
    print(f"Decryption Time: {dec_time:.6f} sec")
Processing Short Record (Size: 34 bytes)
Decryption Correct: True
Encryption Time: 0.002062 sec
Decryption Time: 0.001286 sec
Processing Medium Record (Size: 500 bytes)
Decryption Correct: True
Encryption Time: 0.001563 sec
Decryption Time: 0.001019 sec
Processing Large Record (Size: 5120 bytes)
Decryption Correct: True
Encryption Time: 0.001574 sec
Decryption Time: 0.001147 sec
1.
You are conducting a study to evaluate the performance and security of RSA and ElGamal 
encryption algorithms in securing communication for a government agency. Implement 
both RSA (using 2048-bit keys) and ElGamal (using the secp256r1 curve) encryption 
schemes to encrypt and decrypt sensitive messages exchanged between agencies. 


Measure the time taken for key generation, encryption, and decryption processes for 
messages of various sizes (e.g., 1 KB, 10 KB). Compare the computational efficiency and 
overhead of RSA and ElGamal algorithms. Perform the same for ECC with RSA and 
ElGamal.
# ---------- Imports ----------
import time
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, 
modes
# =====================================================
# RSA PERFORMANCE TEST
# =====================================================
message = b"Performance Comparison Test"
# Key Generation
start = time.perf_counter()
rsa_key = RSA.generate(2048)
rsa_public = rsa_key.publickey()
rsa_private = rsa_key
rsa_keygen_time = time.perf_counter() - start
# Encryption
rsa_cipher = PKCS1_OAEP.new(rsa_public)
start = time.perf_counter()
rsa_ciphertext = rsa_cipher.encrypt(message)
rsa_enc_time = time.perf_counter() - start
# Decryption
rsa_dec_cipher = PKCS1_OAEP.new(rsa_private)
start = time.perf_counter()
rsa_decrypted = rsa_dec_cipher.decrypt(rsa_ciphertext)
rsa_dec_time = time.perf_counter() - start
# =====================================================
# ECC PERFORMANCE TEST (ECIES Style)
# =====================================================
# Key Generation
start = time.perf_counter()
ecc_private = ec.generate_private_key(ec.SECP256R1())
ecc_public = ecc_private.public_key()


ecc_keygen_time = time.perf_counter() - start
# Encryption
start = time.perf_counter()
ephemeral_private = ec.generate_private_key(ec.SECP256R1())
shared_secret = ephemeral_private.exchange(ec.ECDH(), ecc_public)
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'performance'
).derive(shared_secret)
iv = os.urandom(12)
encryptor = Cipher(
    algorithms.AES(aes_key),
    modes.GCM(iv)
).encryptor()
ecc_ciphertext = encryptor.update(message) + encryptor.finalize()
tag = encryptor.tag
ecc_enc_time = time.perf_counter() - start
# Decryption
start = time.perf_counter()
shared_secret_dec = ecc_private.exchange(ec.ECDH(), 
ephemeral_private.public_key())
aes_key_dec = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'performance'
).derive(shared_secret_dec)
decryptor = Cipher(
    algorithms.AES(aes_key_dec),
    modes.GCM(iv, tag)
).decryptor()
ecc_decrypted = decryptor.update(ecc_ciphertext) + 
decryptor.finalize()
ecc_dec_time = time.perf_counter() - start
# =====================================================


# OUTPUT RESULTS
# =====================================================
print("----- RSA Results -----")
print(f"Key Generation Time: {rsa_keygen_time:.6f} sec")
print(f"Encryption Time:     {rsa_enc_time:.6f} sec")
print(f"Decryption Time:     {rsa_dec_time:.6f} sec")
print("\n----- ECC Results -----")
print(f"Key Generation Time: {ecc_keygen_time:.6f} sec")
print(f"Encryption Time:     {ecc_enc_time:.6f} sec")
print(f"Decryption Time:     {ecc_dec_time:.6f} sec")
print("\nVerification:")
print("RSA Correct:", rsa_decrypted == message)
print("ECC Correct:", ecc_decrypted == message)
----- RSA Results -----
Key Generation Time: 6.067540 sec
Encryption Time:     0.004390 sec
Decryption Time:     0.021988 sec
----- ECC Results -----
Key Generation Time: 0.000749 sec
Encryption Time:     0.001996 sec
Decryption Time:     0.001470 sec
Verification:
RSA Correct: True
ECC Correct: True
```
