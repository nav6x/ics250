# End-Semester Question Bank Solutions: 3-Marker Answers (Q15 to Q28)

[← Back to Course README](../README.md)

- [Question 15: Passive vs. Active Attacks](#question-15)
- [Question 16: Euler's Theorem Computation (5^202 mod 133)](#question-16)
- [Question 17: Triple DES (3DES) & MitM Attack on 2DES](#question-17)
- [Question 18: HMAC Construction & Security Advantages](#question-18)
- [Question 19: PRNG in Counter (CTR) Mode vs. OFB](#question-19)
- [Question 20: DES Strength & S-Box Role](#question-20)
- [Question 21: OFB vs. CTR Mode Comparison](#question-21)
- [Question 22: Fermat's Little Theorem Calculations](#question-22)
- [Question 23: SHA-512 Construction, Padding & Avalanche Effect](#question-23)
- [Question 24: Secure Cloud Storage Scheme (AES-XTS vs. CBC)](#question-24)
- [Question 25: Playfair Cipher (INNOVATION / MONARCHY)](#question-25)
- [Question 26: Confusion and Diffusion in Feistel Ciphers](#question-26)
- [Question 27: Birthday Paradox & Hash Collision Security](#question-27)
- [Question 28: Digital Signature Standard (DSS) Key Relationship](#question-28)

---

## Question 15
**Question**: Distinguish between passive attacks and active attacks on a cryptographic system. Analyze which type is harder to detect and why, using examples from network sniffing and message modification.

### Solution:
- **Passive Attacks**: Goal is to obtain information without modifying data or altering system state (e.g., snooping, network sniffing, traffic analysis).
- **Active Attacks**: Goal is to alter data streams or disrupt system operations (e.g., message modification, masquerading, replay, DoS).
- **Detection Comparison**: **Passive attacks are significantly harder to detect** because the system operates completely normally without leaving audit logs or data corruption. Active attacks are easier to detect via checksums, MAC verification failures, or IDS logs.

---

## Question 16
**Question**: Apply Euler's Theorem to compute $5^{202} \pmod{133}$. Factorize 133, verify the conditions, calculate $\phi(133)$, and show the reduction of the exponent.

### Solution:
1. **Factorization**: $133 = 7 \times 19$.
2. **Verify Condition**: $\gcd(5, 133) = 1$ (coprime).
3. **Calculate $\phi(133)$**: $\phi(133) = (7 - 1)(19 - 1) = 6 \times 18 = \mathbf{108}$.
4. **Euler's Theorem**: $5^{108} \equiv 1 \pmod{133}$.
5. **Exponent Reduction**:
   $$202 = 1 \times 108 + 94 \implies 5^{202} \equiv 5^{94} \pmod{133}$$
   Computing via repeated squaring ($94 = 64 + 16 + 8 + 4 + 2$):
   - $5^2 = 25$
   - $5^4 = 625 \equiv 93 \pmod{133}$
   - $5^8 = 93^2 \equiv 4 \pmod{133}$
   - $5^{16} = 16 \pmod{133}$
   - $5^{64} \equiv 100 \pmod{133}$
   $$5^{94} \equiv (100 \times 16 \times 4 \times 93 \times 25) \pmod{133} = \mathbf{93}$$
   **Result**: $5^{202} \equiv \mathbf{93} \pmod{133}$.

---

## Question 17
**Question**: Analyze how Triple DES (3DES) improves security over single DES. Explain the Meet-in-the-Middle (MitM) attack on Double DES and why 3DES with three keys is resistant to it.

### Solution:
1. **3DES Improvement**: Passes data through 3 DES stages ($C = E_{K3}(D_{K2}(E_{K1}(P)))$), expanding key size to 168 bits.
2. **MitM Attack on Double DES**: Double DES ($C = E_{K2}(E_{K1}(P))$) rearranges to $D_{K2}(C) = E_{K1}(P) = X$. An attacker encrypts $P$ under all $2^{56}$ $K_1$ values and decrypts $C$ under all $2^{56}$ $K_2$ values, searching for matching intermediate state $X$. This reduces 2DES security from $2^{112}$ to $2^{57}$ operations!
3. **3DES Resistance**: MitM requires matching intermediate states across 3 cipher stages, raising attack complexity to $2^{112}$ operations.

---

## Question 18
**Question**: Explain the construction of HMAC (Hash-based Message Authentication Code). State two distinct security advantages HMAC offers over a simple keyed hash.

### Solution:
1. **Construction**:
   $$\text{HMAC}_K(M) = H\Big( (K^+ \oplus \text{opad}) \mathbin{\Vert} H\big( (K^+ \oplus \text{ipad}) \mathbin{\Vert} M \big) \Big)$$
2. **Two Advantages**:
   - **Prevents Length Extension Attacks**: Simple keyed hashes ($H(K \Vert M)$) are vulnerable to length extension attacks. HMAC's nested structure completely eliminates this.
   - **Algorithm Independence**: HMAC's security relies on the hash function's one-way property without requiring strong collision resistance, allowing hash functions to be swapped easily.

---

## Question 19
**Question**: Explain how pseudorandom number generation works using a Block Cipher in Counter (CTR) Mode. Compare its operation with Output Feedback (OFB) mode for random bit generation.

### Solution:
1. **CTR Mode PRNG**: Encrypts an incrementing counter $T_i = IV + i$: $R_i = E_K(T_i)$. The encrypted outputs $R_i$ form a pseudorandom bitstream.
2. **Comparison with OFB**:
   - **Parallelizability & Random Access**: CTR mode allows instant random access and parallel generation of any block $i$. OFB is strictly sequential ($O_i = E_K(O_{i-1})$).
   - **Period**: CTR mode guarantees a full period of $2^b$ blocks before repeating.

---

## Question 20
**Question**: Analyze the strength of DES against brute-force attacks, differential cryptanalysis, and linear cryptanalysis. Explain why S-boxes are critical in resisting these attacks.

### Solution:
1. **Brute-Force**: 56-bit key ($2^{56} \approx 72 \text{ trillion keys}$) is broken in hours by modern hardware.
2. **Differential Cryptanalysis**: Analyzes output difference propagation $\Delta C$ for chosen input differences $\Delta P$. Requires $2^{47}$ chosen plaintexts.
3. **Linear Cryptanalysis**: Finds linear approximations between plaintext, ciphertext, and key bits. Requires $2^{43}$ known plaintexts (Matsui 1993).
4. **S-Box Role**: S-Boxes are the **only non-linear elements** in DES. They introduce confusion, preventing linear equations from expressing the cipher.

---

## Question 21
**Question**: Compare Output Feedback (OFB) and Counter (CTR) modes of operation. Discuss parallelizability, error propagation, and suitability for high-speed network encryption.

### Solution:
- **Parallelizability**: CTR is fully parallelizable for both encryption and decryption. OFB is strictly sequential.
- **Error Propagation**: Neither mode propagates bit errors (a flipped bit in ciphertext affects only the single corresponding plaintext bit).
- **High-Speed Suitability**: CTR mode is vastly superior for high-speed multi-gigabit networks due to parallel execution and random access.

---

## Question 22
**Question**: Apply Fermat's Little Theorem to compute:
(a) $2^{120} \pmod{101}$
(b) The last digit of $3^{500}$.
State the formal theorem and the required conditions.

### Solution:
1. **Theorem**: If $p$ is prime and $p \nmid a$, then $a^{p-1} \equiv 1 \pmod p$.
2. **(a) $2^{120} \pmod{101}$**: $p=101$ prime. $2^{100} \equiv 1 \pmod{101}$.  
   $$2^{120} = 2^{100} \cdot 2^{20} \equiv 1 \cdot (2^{10})^2 \equiv 14^2 = 196 \equiv \mathbf{95} \pmod{101}$$
3. **(b) Last digit of $3^{500}$**: Evaluates $3^{500} \pmod{10}$. By Euler's theorem ($\phi(10)=4$), $3^4 \equiv 1 \pmod{10}$.  
   $$3^{500} = (3^4)^{125} \equiv 1^{125} \equiv \mathbf{1} \pmod{10}$$  
   Last digit is **1**.

---

## Question 23
**Question**: Explain the construction of the SHA-512 hash algorithm, specifically addressing message padding, the definition of initial hash constants, and the avalanche effect.

### Solution:
1. **Message Padding**: Padded with `1` bit followed by $0$s until length $\equiv 896 \pmod{1024}$, ending with 128-bit length field.
2. **Initial Constants**: 8 64-bit words derived from fractional parts of square roots of first 8 primes.
3. **Avalanche Effect**: Changing a single input bit diffuses across 80 rounds, changing $\approx 50\%$ of digest bits unpredictably.

---

## Question 24
**Question**: Design a secure cloud storage scheme. Justify the choice of AES-XTS mode over CBC mode for encrypting data at rest on a disk.

### Solution:
- **Cloud Storage Scheme**: Client-side zero-knowledge encryption before upload.
- **AES-XTS vs CBC**: CBC requires IV chaining and padding, preventing random block access on disk. AES-XTS uses a sector address "tweak" $T$, allowing efficient independent random sector read/writes without ciphertext expansion.

---

## Question 25
**Question**: Describe the Playfair Cipher. Encrypt the word "INNOVATION" using the keyword "MONARCHY" and explain the rules for dealing with repeating letters and odd-length strings.

### Solution:
1. **Matrix (`MONARCHY`)**:
   ```
   M O N A R
   C H Y B D
   E F G I K
   L P Q S T
   U V W X Z
   ```
2. **Formatting**: `IN N O V A T I O N` $\to$ insert bogus `X` for double `N` $\to$ `IN NO VA TI ON`.
3. **Encryption Rules**:
   - `IN` (rectangle) $\to$ **GA**
   - `NO` (same row) $\to$ **AN**
   - `VA` (rectangle) $\to$ **XO**
   - `TI` (rectangle) $\to$ **SK**
   - `ON` (same row) $\to$ **NA**
   **Ciphertext**: `GA AN XO SK NA`

---

## Question 26
**Question**: Explain the concept of "Confusion" and "Diffusion" as proposed by Claude Shannon. Identify which components in a typical Feistel cipher (like DES) contribute to each.

### Solution:
- **Confusion**: Obscures key-ciphertext relationship. Contributed by **S-Boxes** (Substitution).
- **Diffusion**: Spreads plaintext statistics across ciphertext. Contributed by **P-Boxes, ShiftRows, MixColumns, and round swapping** (Permutation).

---

## Question 27
**Question**: Discuss the Birthday Paradox and its implications for the security of hash functions. Explain why a 128-bit hash might only provide 64 bits of security against collision attacks.

### Solution:
- **Birthday Paradox**: Finding any collision among $N$ possibilities requires only $\approx \sqrt{N}$ attempts.
- **Implication**: For a 128-bit hash ($N = 2^{128}$), collision attacks require only $\sqrt{2^{128}} = 2^{64}$ hashes. Thus, a 128-bit hash provides only **64 bits of security** against collisions.

---

## Question 28
**Question**: Describe the Digital Signature Standard (DSS). Explain the relationship between the private key used for signing and the public key used for verification.

### Solution:
- **DSS Architecture**: Uses Digital Signature Algorithm (DSA) based on ElGamal/Schnorr over prime fields.
- **Key Relationship**: Signer uses private key $d$ to create signature $(r, s)$ on hash $H(M)$. Verifier uses public key $(e_1, e_2, p, q)$ to confirm $g^{H(M)w} e_2^{rw} \equiv r \pmod p$.
