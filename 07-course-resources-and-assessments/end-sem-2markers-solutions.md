# End-Semester Question Bank Solutions: 2-Marker Answers (Q29 to Q42)

[← Back to Course README](../README.md)

- [Question 29: Security Services & Use Cases](#question-29)
- [Question 30: Symmetric Cipher Model & Kerckhoffs's Principle](#question-30)
- [Question 31: Chinese Remainder Theorem Solution](#question-31)
- [Question 32: MDC vs. MAC Comparison](#question-32)
- [Question 33: AES Round Function Transformations](#question-33)
- [Question 34: Cryptanalysis Attack Models](#question-34)
- [Question 35: RC4 Stream Cipher KSA & PRGA](#question-35)
- [Question 36: ElGamal vs. RSA Comparison](#question-36)
- [Question 37: Proof of \phi(pq) & \phi(2211) Computation](#question-37)
- [Question 38: One-Way Hash Function Role in Digital Signatures](#question-38)
- [Question 39: Discrete Logarithm Problem Definition](#question-39)
- [Question 40: Cryptographic Nonce & Replay Prevention](#question-40)
- [Question 41: Block Cipher vs. Stream Cipher](#question-41)
- [Question 42: Steganography vs. Cryptography](#question-42)

---

## Question 29
**Question**: Explain the concept of Security Services in network security and list any four services with a brief use case for each.

### Solution:
Security services are mechanisms recommended by ITU-T X.800 to prevent security attacks:
1. **Data Confidentiality**: Prevents snooping (e.g. encrypting web payloads via TLS).
2. **Data Integrity**: Ensures message is unmodified (e.g. verifying HMAC tags).
3. **Authentication**: Confirms entity identity (e.g. 2FA login verification).
4. **Nonrepudiation**: Prevents denial of origin (e.g. signing contracts via RSA private key).

---

## Question 30
**Question**: Describe the Symmetric Cipher Model using a block diagram and state two essential requirements for a secure symmetric cipher.

### Solution:
```
Plaintext → [Encryption E_K] → Ciphertext → [Decryption D_K] → Plaintext 
                 ▲                               ▲ 
                 └─── [Secret Key K (Shared)] ───┘ 
```
**Two Essential Requirements (Kerckhoffs's Principle)**:
1. Security must depend strictly on the secrecy of the key, not the algorithm.
2. Guessing the key must be computationally infeasible.

---

## Question 31
**Question**: Apply the Chinese Remainder Theorem (CRT) to solve: $x \equiv 1 \pmod 3, x \equiv 4 \pmod 5, x \equiv 6 \pmod 7$.

### Solution:
1. $M = 3 \times 5 \times 7 = 105$.
2. $M_1 = 35$, $M_2 = 21$, $M_3 = 15$.
3. Inverses $y_i = M_i^{-1} \pmod{m_i}$:
   - $35 y_1 \equiv 2 y_1 \equiv 1 \pmod 3 \implies y_1 = 2$
   - $21 y_2 \equiv 1 y_2 \equiv 1 \pmod 5 \implies y_2 = 1$
   - $15 y_3 \equiv 1 y_3 \equiv 1 \pmod 7 \implies y_3 = 1$
4. $x = (1 \times 35 \times 2 + 4 \times 21 \times 1 + 6 \times 15 \times 1) \bmod 105 = 244 \bmod 105 = \mathbf{34}$.

---

## Question 32
**Question**: Compare Modification Detection Codes (MDC) and Message Authentication Codes (MAC) in terms of purpose and key management.

### Solution:
- **Purpose**: MDC proves data integrity only; MAC proves data integrity AND data origin authentication.
- **Key Management**: MDC is unkeyed (requires a safe channel for hash transfer); MAC uses a shared secret key.

---

## Question 33
**Question**: Describe the four transformation steps of the AES round function: SubBytes, ShiftRows, MixColumns, and AddRoundKey.

### Solution:
1. **SubBytes**: Non-linear byte substitution using S-Box for confusion.
2. **ShiftRows**: Cyclic left-shifting of State matrix rows (Row 1 by 1, Row 2 by 2, Row 3 by 3 bytes).
3. **MixColumns**: Galois Field $GF(2^8)$ column multiplication for diffusion.
4. **AddRoundKey**: XORing State matrix with 128-bit round subkey.

---

## Question 34
**Question**: Define Cryptanalysis and briefly describe Ciphertext-Only, Known-Plaintext, Chosen-Plaintext, and Chosen-Ciphertext attacks.

### Solution:
**Cryptanalysis** is the science of breaking cryptosystems without knowing the key.
1. **Ciphertext-Only**: Attacker has only ciphertext.
2. **Known-Plaintext**: Attacker has known plaintext/ciphertext pairs.
3. **Chosen-Plaintext**: Attacker chooses plaintexts to be encrypted.
4. **Chosen-Ciphertext**: Attacker chooses ciphertexts to be decrypted.

---

## Question 35
**Question**: Describe the structure of the RC4 stream cipher, focusing on the Key Scheduling Algorithm (KSA) and the Pseudo-Random Generation Algorithm (PRGA).

### Solution:
- **KSA**: Scrambles 256-byte State array $S$ using key $K$: `j = (j + S[i] + K[i mod keylen]) mod 256; swap(S[i], S[j])`.
- **PRGA**: Generates 1 byte of keystream per step: `i = (i+1) mod 256; j = (j + S[i]) mod 256; swap(S[i], S[j]); output(S[(S[i] + S[j]) mod 256])`.
- **Security Note**: RC4 is deprecated due to initial keystream biases and WEP/TLS exploits.

---

## Question 36
**Question**: Compare ElGamal with RSA based on mathematical hardness assumptions and ciphertext expansion.

### Solution:
- **Hardness**: RSA relies on Integer Factorization (IFP); ElGamal relies on Discrete Logarithms (DLP).
- **Expansion**: RSA ciphertext has $1 \times$ size; ElGamal ciphertext has $2 \times$ size (pair $c_1, c_2$).

---

## Question 37
**Question**: Use Euler's Totient Function to prove that $\phi(pq) = (p-1)(q-1)$ for distinct primes and compute $\phi(2211)$ where $2211 = 33 \times 67$.

### Solution:
1. **Proof**: Non-coprime integers $\le pq$ are $q$ multiples of $p$ and $p$ multiples of $q$, overlapping at $pq$.  
   $$\phi(pq) = pq - (p + q - 1) = (p - 1)(q - 1)$$
2. **Computation**: $2211 = 3 \times 11 \times 67$.  
   $$\phi(2211) = (3 - 1)(11 - 1)(67 - 1) = 2 \times 10 \times 66 = \mathbf{1320}$$

---

## Question 38
**Question**: Explain the role of a one-way hash function in a digital signature scheme and why signing the hash is more efficient than signing the whole message.

### Solution:
1. **Role**: Compresses arbitrary messages into a fixed-size digest $h = H(M)$.
2. **Efficiency**: Asymmetric signing ($M^d \bmod n$) is slow. Hashing reduces long messages to 256 bits quickly, executing the heavy asymmetric operation only once.

---

## Question 39
**Question**: Define the "Discrete Logarithm Problem" and name one cryptographic protocol that relies on its difficulty.

### Solution:
- **Definition**: Given $y = a^x \pmod n$, finding exponent $x = \log_a y \pmod n$ is computationally infeasible.
- **Protocol**: Diffie-Hellman Key Exchange (or ElGamal).

---

## Question 40
**Question**: What is a "Nonce" in cryptography? Provide one example of its use in preventing replay attacks.

### Solution:
- **Nonce**: Number used Once — a random number generated fresh per session.
- **Replay Prevention**: Server sends fresh Nonce $N$. Client responds with $\text{Hash}(\text{Password} \Vert N)$. Captured responses are invalid for future sessions because the server issues a new Nonce.

---

## Question 41
**Question**: Explain the difference between a "Block Cipher" and a "Stream Cipher" with one example of each.

### Solution:
- **Block Cipher**: Encrypts fixed-size blocks (e.g. 128 bits) simultaneously. *Example*: **AES**.
- **Stream Cipher**: Encrypts continuous stream symbol-by-symbol via XOR. *Example*: **RC4**.

---

## Question 42
**Question**: Briefly explain the concept of Steganography and how it differs from traditional Cryptography.

### Solution:
- **Steganography**: Hides the **existence** of a message inside a cover medium (e.g., image LSBs).
- **Difference**: Cryptography scrambles data into unreadable ciphertext (visible, but uninterpretable); Steganography conceals the transmission entirely so observers do not suspect communication.
