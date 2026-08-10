# LAB 7: Partial Homomorphic Encryption

[← Back to Course README](../README.md)

- [Official ICAS Cyber Security Laboratory Manual & Record](#official-icas-cyber-security-laboratory-manual-record)
> **Topic**: LAB 7: Partial Homomorphic Encryption: Official ICAS Cyber Security Laboratory Manual & Record, ---------- Key Generation ----------, λ (lambda), μ (mu)

---

## Official ICAS Cyber Security Laboratory Manual & Record



```markdown

Lab Exercises

1.

Implement the Paillier encryption scheme in Python. Encrypt two integers (e.g., 15 and 

25) using your implementation of the Paillier encryption scheme. Print the ciphertexts. 





Perform an addition operation on the encrypted integers without decrypting them. Print 

the result of the addition in encrypted form. Decrypt the result of the addition and verify 

that it matches the sum of the original integers.

import random

from Crypto.Util.number import getPrime, inverse

# ---------- Key Generation ----------

def generate_paillier_keypair(bits=512):

    p = getPrime(bits // 2)

    q = getPrime(bits // 2)

    n = p * q

    n_sq = n * n

    g = n + 1

    # λ (lambda)

    lmbda = (p - 1) * (q - 1)

    # μ (mu)

    mu = inverse(lmbda, n)

    return (n, g, n_sq), (lmbda, mu)

# ---------- Encryption ----------

def paillier_encrypt(pub_key, m):

    n, g, n_sq = pub_key

    r = random.randint(1, n - 1)

    c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq

    return c

# ---------- Decryption ----------

def paillier_decrypt(pub_key, priv_key, c):

    n, g, n_sq = pub_key

    lmbda, mu = priv_key

    x = pow(c, lmbda, n_sq)

    L = (x - 1) // n

    m = (L * mu) % n

    return m

# ---------- Homomorphic Addition ----------

def homomorphic_add(pub_key, c1, c2):

    n, g, n_sq = pub_key

    return (c1 * c2) % n_sq





# ---------- Main Program ----------

print("\n--- Paillier Homomorphic Addition ---\n")

# Step 1: Generate keys

pub_key, priv_key = generate_paillier_keypair()

# Step 2: Original numbers

num1, num2 = 15, 25

print(f"Original Numbers: {num1}, {num2}")

# Step 3: Encrypt

c1 = paillier_encrypt(pub_key, num1)

c2 = paillier_encrypt(pub_key, num2)

print(f"Encrypted c1: {str(c1)[:25]}...")

print(f"Encrypted c2: {str(c2)[:25]}...")

# Step 4: Add without decrypting

c_sum = homomorphic_add(pub_key, c1, c2)

print(f"Encrypted Sum: {str(c_sum)[:25]}...")

# Step 5: Decrypt result

decrypted_sum = paillier_decrypt(pub_key, priv_key, c_sum)

print(f"\nDecrypted Result: {decrypted_sum}")

print(f"Expected Result: {num1 + num2}")

print(f"Verification: {decrypted_sum == (num1 + num2)}")

--- Paillier Homomorphic Addition ---

Original Numbers: 15, 25

Encrypted c1: 2248499035634700534942116...

Encrypted c2: 2111251240410197199776657...

Encrypted Sum: 3371378416293106429221086...

Decrypted Result: 40

Expected Result: 40

Verification: True

1.

Utilize the multiplicative homomorphic property of RSA encryption. Implement a basic 

RSA encryption scheme in Python. Encrypt two integers (e.g., 7 and 3) using your 

implementation of the RSA encryption scheme. Print the ciphertexts. Perform a 

multiplication operation on the encrypted integers without decrypting them. Print the 

result of the multiplication in encrypted form. Decrypt the result of the multiplication 

and verify that it matches the product of the original integers.

# ---------- Imports ----------

from Crypto.PublicKey import RSA

# ---------- Homomorphic Function ----------





def rsa_homomorphic_multiply(c1, c2, n):

    # Property: E(m1) * E(m2) mod n = E(m1 * m2)

    return (c1 * c2) % n

# ---------- Main Execution ----------

print("\n--- RSA Multiplicative Homomorphism ---\n")

# Generate RSA key (1024 bits)

key = RSA.generate(1024)

n, e, d = key.n, key.e, key.d

num1, num2 = 7, 3

print(f"Original Integers: {num1} and {num2}")

# ---------- Encryption ----------

# c = m^e mod n

c1 = pow(num1, e, n)

c2 = pow(num2, e, n)

print(f"Ciphertext 1 (truncated): {str(c1)[:30]}...")

print(f"Ciphertext 2 (truncated): {str(c2)[:30]}...")

# ---------- Homomorphic Operation ----------

# Perform multiplication in the encrypted domain

c_prod = rsa_homomorphic_multiply(c1, c2, n)

print(f"Encrypted Product (truncated): {str(c_prod)[:30]}...")

# ---------- Decryption & Verification ----------

# m = c^d mod n

decrypted_prod = pow(c_prod, d, n)

print(f"\nDecrypted Result: {decrypted_prod}")

print(f"Verification: {num1} * {num2} == {decrypted_prod} -> {num1 * 

num2 == decrypted_prod}")

--- RSA Multiplicative Homomorphism ---

Original Integers: 7 and 3

Ciphertext 1 (truncated): 694983134098025895999645190506...

Ciphertext 2 (truncated): 871979609162554427244976049670...

Encrypted Product (truncated): 187277306790245157545521364695...

Decrypted Result: 21

Verification: 7 * 3 == 21 -> True





Additional Questions

Implement similar exercise for other PHE operations (like homomorphic multiplication using 

ElGamal) or explore different functionalities within Paillier.

1a: Homomorphic Multiplication (ElGamal Cryptosystem): Implement ElGamal encryption and 

demonstrate homomorphic multiplication on encrypted messages. (ElGamal supports 

multiplication but not homomorphic addition.)

# ---------- Imports ----------

import random

from Crypto.Util.number import getPrime, inverse

# ---------- Key Generation ----------

def generate_elgamal_keypair(bits=256):

    p = getPrime(bits)

    g = 2

    x = random.randint(2, p - 2)

    y = pow(g, x, p)

    return (p, g, y), x

# ---------- Encryption ----------

def elgamal_encrypt(pub_key, m):

    p, g, y = pub_key

    k = random.randint(2, p - 2)

    c1 = pow(g, k, p)

    c2 = (m * pow(y, k, p)) % p

    return (c1, c2)

# ---------- Decryption ----------

def elgamal_decrypt(pub_key, priv_key, ciphertext):

    p, g, y = pub_key

    x = priv_key

    c1, c2 = ciphertext

    

    # Decryption: m = c2 * (c1^x)^-1 mod p

    s = pow(c1, x, p)

    m = (c2 * inverse(s, p)) % p

    return m

# ---------- Homomorphic Multiplication ----------

def elgamal_homomorphic_multiply(pub_key, cipher1, cipher2):

    # Multiplicative Property: E(m1) * E(m2) = (c1_a * c1_b, c2_a * 

c2_b) = E(m1 * m2)

    p, _, _ = pub_key

    c1_a, c2_a = cipher1

    c1_b, c2_b = cipher2

    

    c1_res = (c1_a * c1_b) % p

    c2_res = (c2_a * c2_b) % p





    return (c1_res, c2_res)

# ---------- Main Execution ----------

print("--- ElGamal Homomorphic Multiplication ---")

# Step 1: Setup Keys

pub, priv = generate_elgamal_keypair()

# Step 2: Define and Encrypt Values

val1, val2 = 10, 5

print(f"Original Values: {val1}, {val2}")

enc1 = elgamal_encrypt(pub, val1)

enc2 = elgamal_encrypt(pub, val2)

# Step 3: Perform multiplication on the ciphertexts

enc_product = elgamal_homomorphic_multiply(pub, enc1, enc2)

# Step 4: Decrypt the product to verify the operation

dec_product = elgamal_decrypt(pub, priv, enc_product)

print(f"Decrypted Product: {dec_product}")

print(f"Verified: {val1} * {val2} == {dec_product} -> {val1 * val2 == 

dec_product}\n")

--- ElGamal Homomorphic Multiplication ---

Original Values: 10, 5

Decrypted Product: 50

Verified: 10 * 5 == 50 -> True

1b: Secure Data Sharing (Paillier): Simulate a scenario where two parties share encrypted data 

and perform calculations on the combined data without decryption.

# ---------- Helper Functions (Paillier) ----------

def generate_paillier_keypair(bits=512):

    p = getPrime(bits // 2)

    q = getPrime(bits // 2)

    n = p * q

    n_sq = n * n

    g = n + 1

    lmbda = (p - 1) * (q - 1)

    mu = inverse(lmbda, n)

    return (n, g, n_sq), (lmbda, mu)

def paillier_encrypt(pub_key, m):

    n, g, n_sq = pub_key

    r = random.randint(1, n - 1)

    c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq

    return c





def paillier_decrypt(pub_key, priv_key, c):

    n, g, n_sq = pub_key

    lmbda, mu = priv_key

    x = pow(c, lmbda, n_sq)

    L = (x - 1) // n

    m = (L * mu) % n

    return m

def paillier_homomorphic_add(pub_key, c1, c2):

    n_sq = pub_key[2]

    return (c1 * c2) % n_sq

# ---------- Main Execution ----------

print("--- Secure Data Sharing (Paillier) ---")

# Step 1: Central Health Dept generates keypair

health_dept_pub, health_dept_priv = 

generate_paillier_keypair(bits=512)

# Step 2: Define hospital data

hospital_a_patients = 150

hospital_b_patients = 205

# ---------- Hospital Side (Encryption) ----------

print(f"[Hospital A] Encrypting its patient count 

({hospital_a_patients})...")

enc_a = paillier_encrypt(health_dept_pub, hospital_a_patients)

print(f"[Hospital B] Encrypting its patient count 

({hospital_b_patients})...")

enc_b = paillier_encrypt(health_dept_pub, hospital_b_patients)

# ---------- Cloud Server Side (Homomorphic Addition) ----------

print("\n[Cloud Server] Received encrypted data. Performing 

homomorphic addition...")

enc_total = paillier_homomorphic_add(health_dept_pub, enc_a, enc_b)

print("-> Computation complete. Encrypted aggregate sent to Health 

Dept.")

# ---------- Health Dept Side (Decryption) ----------

final_total = paillier_decrypt(health_dept_pub, health_dept_priv, 

enc_total)

print(f"\n[Health Dept] Decrypted Regional Total: {final_total}")

print(f"Data Sharing Verification: {hospital_a_patients} + 

{hospital_b_patients} == {final_total}")

--- Secure Data Sharing (Paillier) ---

[Hospital A] Encrypting its patient count (150)...





[Hospital B] Encrypting its patient count (205)...

[Cloud Server] Received encrypted data. Performing homomorphic 

addition...

-> Computation complete. Encrypted aggregate sent to Health Dept.

[Health Dept] Decrypted Regional Total: 355

Data Sharing Verification: 150 + 205 == 355

1c: Secure Thresholding (PHE): Explore how PHE can be used for secure multi-party 

computation, where a certain number of parties need to collaborate on a computation without 

revealing their individual data.

# ---------- Main Execution ----------

print("--- Add Secure Thresholding / MPC (PHE) ---")

# Step 1: Authority generates Paillier keys

pub_key, priv_key = generate_paillier_keypair(bits=512)

# Step 2: Participants cast binary votes (1 for Yes, 0 for No)

voters = [1, 0, 1] 

print(f"Voters casting encrypted shares: {voters}")

encrypted_votes = [paillier_encrypt(pub_key, v) for v in voters]

# Step 3: Tallying (Multi-Party Computation)

# Summing encrypted votes without decrypting them

final_enc_tally = encrypted_votes[0]

for i in range(1, len(encrypted_votes)):

    final_enc_tally = paillier_homomorphic_add(pub_key, 

final_enc_tally, encrypted_votes[i])

# Step 4: Tally Decryption

tally_result = paillier_decrypt(pub_key, priv_key, final_enc_tally)

print(f"\nFinal Decrypted Tally: {tally_result} 'Yes' votes")

print(f"Privacy Verification: Individual votes remained encrypted 

throughout computation.")

--- Add Secure Thresholding / MPC (PHE) ---

Voters casting encrypted shares: [1, 0, 1]

Final Decrypted Tally: 2 'Yes' votes

Privacy Verification: Individual votes remained encrypted throughout 

computation.

1d: Performance Analysis (Benchmarking): Compare the performance of different PHE schemes 

(Paillier and ElGamal) for various operations.





# ---------- Imports ----------

import time

# ---------- Benchmarking Function ----------

def benchmark_phe():

    print("--- Add Performance Analysis (Benchmarking) ---")

    

    # 1. Paillier Timing (512-bit)

    start = time.perf_counter()

    pub_p, priv_p = generate_paillier_keypair(bits=512)

    p_keygen = time.perf_counter() - start

    start = time.perf_counter()

    c_p = paillier_encrypt(pub_p, 100)

    p_enc = time.perf_counter() - start

    # 2. ElGamal Timing (512-bit)

    start = time.perf_counter()

    pub_e, priv_e = generate_elgamal_keypair(bits=512)

    e_keygen = time.perf_counter() - start

    start = time.perf_counter()

    c_e = elgamal_encrypt(pub_e, 100)

    e_enc = time.perf_counter() - start

    # ---------- Results Table ----------

    print(f"{'Metric':<20} | {'Paillier Additive':<25} | {'ElGamal 

(Multiplicative)':<25}")

    print("-" * 80)

    print(f"{'Key Generation (s)':<20} | {p_keygen:<25.6f} | 

{e_keygen:<25.6f}")

    print(f"{'Encryption (s)':<20} | {p_enc:<25.6f} | {e_enc:<25.6f}")

# Run Benchmark

benchmark_phe()

--- Add Performance Analysis (Benchmarking) ---

Metric               | Paillier Additive       | ElGamal 

(Multiplicative) 

----------------------------------------------------------------------

----------

Key Generation (s)   | 0.238903                  | 0.265998            

Encryption (s)       | 0.020231                  | 0.007555

```
