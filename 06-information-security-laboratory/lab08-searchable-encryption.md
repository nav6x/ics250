# LAB 8: Searchable Encryption

[← Back to Course README](../README.md)

- [Official ICAS Cyber Security Laboratory Manual & Record](#official-icas-cyber-security-laboratory-manual-record)
> **Topic**: LAB 8: Searchable Encryption: Official ICAS Cyber Security Laboratory Manual & Record, ---------- Create a Dataset ----------, ---------- AES Encryption and Decryption Functions ----------, Initialize AES in CBC mode

---

## Official ICAS Cyber Security Laboratory Manual & Record

```markdown
Lab Exercise 1: Execute the following for SSE:
1a. Create a dataset: Generate a text corpus of at least ten documents. Each document should 
contain multiple words.
# ---------- Create a Dataset ----------
documents = {
    "doc1": "the quick brown fox jumps over the lazy dog",
    "doc2": "cryptography provides secure communication",
    "doc3": "searchable encryption protects data privacy",
    "doc4": "the lazy dog sleeps all day",
    "doc5": "advanced encryption standard uses symmetric keys",
    "doc6": "cloud servers store encrypted data",
    "doc7": "data privacy is a major concern today",
    "doc8": "the quick brown fox is very clever",
    "doc9": "symmetric encryption is faster than asymmetric",
    "doc10": "inverted indexes make text search highly efficient"
}
print(f"Dataset successfully created with {len(documents)} 
documents.")
Dataset successfully created with 10 documents.
1b. Implement encryption and decryption functions: Use the AES encryption and decryption 
functions.
# ---------- AES Encryption and Decryption Functions ----------
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
def aes_encrypt(key, data):
    # Initialize AES in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), 
AES.block_size))
    return iv, ciphertext
def aes_decrypt(key, iv, ciphertext):
    # Decrypt and unpad data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')


# Generate a 256-bit master key for SSE
sse_master_key = get_random_bytes(32)
print("AES functions defined and 256-bit Master Key generated.")
AES functions defined and 256-bit Master Key generated.
1c. Create an inverted index: Build an inverted index mapping word to the list of document IDs 
containing those words.
•
Encrypt the index using the provided encryption function.
# ---------- Create and Encrypt Inverted Index ----------
def create_sse_index(docs, key):
    index = {}
    
    # Build raw inverted index mapping word hashes to document IDs
    for doc_id, doc_text in docs.items():
        for word in set(doc_text.lower().split()): 
            word_hash = hashlib.sha256(word.encode()).digest()
            if word_hash not in index:
                index[word_hash] = []
            index[word_hash].append(doc_id)
            
    # Encrypt the document IDs within the index
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_doc_ids = []
        for d_id in doc_ids:
            iv, c_text = aes_encrypt(key, d_id)
            encrypted_doc_ids.append((iv, c_text))
        encrypted_index[word_hash] = encrypted_doc_ids
        
    return encrypted_index
sse_enc_index = create_sse_index(documents, sse_master_key)
print("Inverted index successfully built and encrypted using AES.")
Inverted index successfully built and encrypted using AES.
1d. Implement the search function:
•
Take a search query as input.
•
Encrypt the query.
•
Search the encrypted index for matching terms.
•
Decrypt the returned document IDs and display the corresponding documents
# ---------- SSE Search Function ----------
def search_sse(encrypted_index, query, key):
    # Generate trapdoor (hash) for the search query
    query_hash = hashlib.sha256(query.lower().encode()).digest()


    
    if query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[query_hash]
        decrypted_doc_ids = []
        
        # Decrypt matching document IDs
        for iv, c_text in encrypted_doc_ids:
            decrypted_doc_id = aes_decrypt(key, iv, c_text)
            decrypted_doc_ids.append(decrypted_doc_id)
            
        return decrypted_doc_ids
    return []
# Execute search queries
print("--- SSE Search Results ---")
for q in ["encryption", "fox", "blockchain"]:
    results = search_sse(sse_enc_index, q, sse_master_key)
    print(f"Query: '{q}' -> Found in: {results}")
--- SSE Search Results ---
Query: 'encryption' -> Found in: ['doc3', 'doc5', 'doc9']
Query: 'fox' -> Found in: ['doc1', 'doc8']
Query: 'blockchain' -> Found in: []
Lab Exercise 2: Execute the following for PKSE:
2a. Create a dataset:
•
Generate a text corpus of at least ten documents. Each document should contain 
multiple words.
# ---------- Create a Dataset ----------
documents = {
    "doc1": "the quick brown fox jumps over the lazy dog",
    "doc2": "cryptography provides secure communication",
    "doc3": "searchable encryption protects data privacy",
    "doc4": "the lazy dog sleeps all day",
    "doc5": "advanced encryption standard uses symmetric keys",
    "doc6": "cloud servers store encrypted data",
    "doc7": "data privacy is a major concern today",
    "doc8": "the quick brown fox is very clever",
    "doc9": "symmetric encryption is faster than asymmetric",
    "doc10": "inverted indexes make text search highly efficient"
}
print(f"Dataset successfully created with {len(documents)} 
documents.")
Dataset successfully created with 10 documents.


2b. Implement encryption and decryption functions: Use the Paillier cryptosystem for encryption 
and decryption.
# ---------- Paillier Asymmetric Key Functions ----------
import random
from Crypto.Util.number import getPrime, inverse
def generate_paillier_keys(bits=512):
    # Standard Paillier key generation: n = p*q, lambda = (p-1)(q-1)
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    n_sq = n * n
    lmbda = (p - 1) * (q - 1)
    # Using g = n + 1 for simplified mu calculation: mu = lambda^-1 
mod n
    return (n, n + 1, n_sq), (lmbda, inverse(lmbda, n))
def paillier_encrypt(pub_key, m):
    n, g, n_sq = pub_key
    r = random.randint(1, n - 1)
    # E(m) = g^m * r^n mod n^2
    return (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
def paillier_decrypt(pub_key, priv_key, c):
    n, g, n_sq = pub_key
    lmbda, mu = priv_key
    # L(u) = (u-1)/n
    L = (pow(c, lmbda, n_sq) - 1) // n
    # m = L(c^lambda mod n^2) * mu mod n
    return (L * mu) % n
pkse_pub, pkse_priv = generate_paillier_keys(bits=512)
print("Paillier functions defined and Asymmetric Keypair generated.")
Paillier functions defined and Asymmetric Keypair generated.
2c. Create an encrypted index:
•
Build an inverted index mapping word to the list of document IDs containing those 
words.
•
Encrypt the index using the Paillier cryptosystem.
# ---------- Create an Encrypted Inverted Index ----------
import hashlib
def create_pkse_index(docs, pub_key):
    index = {}
    for doc_id, doc_text in docs.items():
        # Convert document ID to integer for Paillier encryption 


(e.g., 'doc1' -> 1)
        doc_int = int(doc_id.replace("doc", "")) 
        
        for word in set(doc_text.lower().split()):
            # Keywords are hashed to serve as index keys
            word_hash = hashlib.sha256(word.encode()).hexdigest()
            if word_hash not in index:
                index[word_hash] = []
            
            # Encrypt the document ID using the Paillier public key
            enc_doc_int = paillier_encrypt(pub_key, doc_int)
            index[word_hash].append(enc_doc_int)
            
    return index
pkse_index = create_pkse_index(documents, pkse_pub)
print("Inverted index successfully built and encrypted using 
Paillier.")
Inverted index successfully built and encrypted using Paillier.
2d. Implement the search function:
•
Take a search query as input.
•
Encrypt the query using the public key.
•
Search the encrypted index for matching terms.
•
Decrypt the returned document IDs using the private key.
# ---------- PKSE Search Function ----------
def search_pkse(encrypted_index, query, pub_key, priv_key):
    # Hash the search query to match the index keys
    query_hash = hashlib.sha256(query.lower().encode()).hexdigest()
    
    if query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[query_hash]
        decrypted_doc_ids = []
        
        for enc_doc in encrypted_doc_ids:
            # Decrypt each document ID using the Paillier private key
            doc_int = paillier_decrypt(pub_key, priv_key, enc_doc)
            decrypted_doc_ids.append(f"doc{doc_int}")
            
        return decrypted_doc_ids
    return []
# Execute and verify search
print("--- PKSE Search Results ---")
for q in ["privacy", "lazy", "hacker"]:
    results = search_pkse(pkse_index, q, pkse_pub, pkse_priv)
    print(f"Query: '{q}' -> Found in: {results}")


--- PKSE Search Results ---
Query: 'privacy' -> Found in: ['doc3', 'doc7']
Query: 'lazy' -> Found in: ['doc1', 'doc4']
Query: 'hacker' -> Found in: []
Additional Questions
1.
Demonstrate how to securely store and transmit data using GnuPG. Additionally, show 
how to create a digital signature for the data and verify the signature after transmission.
# ---------- Imports ----------
import gnupg
import tempfile
import os
# ---------- GnuPG Demonstration Function ----------
def gnupg_demo():
    print("--- GnuPG Secure Storage, Transmission, and Digital 
Signatures ---\n")
    
    # Initialize GPG home directory in a temporary folder for the lab 
environment
    gpg_dir = tempfile.mkdtemp()
    gpg = gnupg.GPG(gnupghome=gpg_dir)
    
    # ---------- Step 1: Generating RSA Keypair ----------
    print("Step 1: Generating RSA Keypair...")
    input_data = gpg.gen_key_input(
        name_email='alice@cyberlab.com',
        passphrase='labpassword',
        key_type='RSA',
        key_length=2048
    )
    key = gpg.gen_key(input_data)
    fingerprint = key.fingerprint
    print(f"Key Generated. Fingerprint: {fingerprint}\n")
    
    # ---------- Step 2: Data Encryption (Confidentiality) ----------
    original_data = "CONFIDENTIAL: Medical Research Results - Patient 
X"
    print(f"Original Data: {original_data}")
    
    # Encrypt the data using the generated public key
    encrypted_data = gpg.encrypt(original_data, 
recipients=[fingerprint])
    print(f"Data Encrypted for Storage/Transmission (Snippet):\
n{str(encrypted_data)[:100]}...\n")
    
    # ---------- Step 3: Digital Signature (Integrity & Authenticity) 
----------


    # Create a detached signature to prove the sender's identity and 
data integrity
    signed_data = gpg.sign(original_data, keyid=fingerprint, 
passphrase='labpassword')
    print(f"Digital Signature Created (Snippet):\n{str(signed_data)
[:100]}...\n")
    
    # ---------- Step 4: Verification After Transmission ----------
    # Simulate receiving the data and verifying the signature
    verification = gpg.verify(str(signed_data))
    
    print("--- Verification After Transmission ---")
    if verification.valid:
        print(f"SUCCESS: Signature is VALID.")
        print(f"Signed by: {verification.username}")
        print(f"Status: Data integrity and authenticity confirmed.")
    else:
        print("FAILED: Signature is INVALID. Data may have been 
tampered with.")
# ---------- Main Execution ----------
try:
    gnupg_demo()
except Exception as e:
    print(f"Error: {e}. Ensure 'python-gnupg' is installed and 'gpg' 
is in your PATH.")
--- GnuPG Secure Storage, Transmission, and Digital Signatures ---
Step 1: Generating RSA Keypair...
Key Generated. Fingerprint: A167C8CAC9D9FCEA5ED5C0BDE1A70CFBB5ABE95F
Original Data: CONFIDENTIAL: Medical Research Results - Patient X
Data Encrypted for Storage/Transmission (Snippet):
-----BEGIN PGP MESSAGE-----
hQEMA+GnDPu1q+lfAQf+NOXXdeHzLvhiQDoIc6jfHiIL5nSUxtq15up+jlQBEGw5
hs4...
Digital Signature Created (Snippet):
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256
CONFIDENTIAL: Medical Research Results - Patient...
--- Verification After Transmission ---
SUCCESS: Signature is VALID.
Signed by: Autogenerated Key <alice@cyberlab.com>
Status: Data integrity and authenticity confirmed.



===================================================
EXACT ICAS CYBER SECURITY LAB MANUAL (ICS 250)
===================================================

 
 
 
 
 
 
 
 
 
 
 
Cyber Security Lab 
IV Semester: BSC in Computer Science and Engineering       
(ICS 250) 
Year: 2026 
 
 
 
ICAS 
MAHE, MANIPAL 
 
 
 
 
 


 
 
 
 
 
International Center For Applied Sciences (ICAS) 
Manipal – 576 104 
 
 
 
 
 
 
 
Certificate 
 
This is to certify that Ms./Mr. …………………...……………………………………      
Reg. No. …..…………………… Section: ……………… Roll No: ………………... has 
satisfactorily completed the lab exercises prescribed for Cyber Security Lab [ICS 250] of 
Second Year BSC in Computer Science and Engineering Degree at ICAS, Manipal, in 
the academic year 2026-2027. 
Date: ……................................... 
 
 
 
 
 
                                   
                                                                                      Signature of the faculty 
                                                         
 


 
 
CONTENTS 
 
Lab 
No. 
Title 
Page 
No. 
Marks 
Remarks 
Sign 
Course Objectives, Outcomes and 
Evaluation Plan 
 
Instructions to the Students 
 
1 Basic Symmetric Key Ciphers 
1 
2 Advanced Symmetric Key Ciphers 
6 
3 Asymmetric Key Ciphers 
14 
4 Advanced Asymmetric Key 
Cryptography 
22 
5 Hashing 
31 
6 Digital Signature 
34 
7 Partial Homomorphic Encryption 
40 
8 Searchable Encryption 
48 
9 Project Design 
56 
10 Project implementation 
57 
11 Testing and validation 
58 
12 References 
59 


 
 
 
iv 
 


 
 
Course Objectives 
• Assess potential system vulnerabilities. 
• Gain practical insight into various algorithms that can provide system, device, and 
network security. 
• Use techniques and tools to fix security vulnerabilities 
Course Outcomes 
  The student should be able to: 
• Implement symmetric and asymmetric cryptographic techniques using appropriate 
libraries or tools to ensure secure communication. 
• Analyze cryptographic hash functions and digital signatures for data integrity and 
authentication. 
• Demonstrate advanced encryption paradigms such as partial homomorphic and 
searchable encryption to address modern security requirements. 
• Design and develop applications that apply information security principles to solve 
real-world problems using suitable tools and techniques. 
Evaluation plan 
 
Internal 
Evaluation   
(60 Marks) 
Record – 14 
Marks 
 
Record Evaluation-1 = 7 Marks 
Record Evaluation-2 = 7 Marks 
Mid-Term - 20 
Marks 
Write-up = 5 Marks 
Execution = 15 Marks 
Project - 10 
Marks 
Project work = 19 Marks   
Program Check- 
07 Marks 
Program check-1 = 7 Marks 
 
 
Final Exam   
(40 Marks) 
Exam - 40 
Marks 
Part 1 – Experiments = 20 Marks 
Part 2 – Project submission = 20 Marks 


 
 
 
INSTRUCTIONS TO THE STUDENTS 
Pre- Lab Session Instructions 
1. Students should carry the Lab Manual Book and the required stationary to every lab 
session 
2. Be on time and follow the institution dress code 
 
3. Must Sign in the log register provided 
 
4. Make sure to occupy the allotted seat and answer the attendance 
 
5. Adhere to the rules and maintain the decorum 
 
 
In- Lab Session Instructions 
 
• Follow the instructions on the allotted exercises 
 
• Show the program and results to the instructors on completion of experiments 
 
• On receiving approval from the instructor, copy the program and results in the Lab 
record 
• Prescribed textbooks and class notes can be kept ready for reference if required 
 
 
General Instructions for the exercises in Lab 
 
• Implement the given exercise individually and not in a group. 
 
• The programs should meet the following criteria: 
 
o Programs should be interactive with appropriate prompt messages, error 
messages if any, and descriptive messages for outputs. 
o Programs should perform input validation (Data type, range error, etc.) and 
give appropriate error messages and suggest corrective actions. 
o Comments should be used to give the statement of the problem and every 
function should indicate the purpose of the function, inputs and outputs. 
o Statements within the program should be properly indented. 
o Use meaningful names for variables and functions. 
o Make use of constants and type definitions wherever needed. 
• Plagiarism (copying from others) is strictly prohibited and would invite severe 
penalty in evaluation.


  
 
 
• The exercises for each week are divided under three sets: 
o Solved exercise 
o Lab exercises - to be completed during lab hours 
o Additional Exercises - to be completed outside the lab or in the lab to enhance 
the skill 
• In case a student misses a lab class, he/she must ensure that the experiment is 
completed during the repetition class with the permission of the faculty concerned 
but credit will be given only to one day’s experiment(s). 
• Students missing out lab on genuine reasons like conference, sport or activities 
assigned by the department or institute will have to take prior permission from the 
HOD to attend additional lab (in other batch) and complete it before the student 
goes on leave. The student could be awarded marks for the write up for that day 
provided he submits it during the immediate next lab. 
• Students who fall sick should get permission from the HOD for evaluating the lab 
records. However, the attendance will not be given for that lab. 
• Students will be evaluated only by the faculty with whom they are registered even 
though they carry out additional experiment in another batch. 
• Presence of the student during the lab end semester exams is mandatory even if the 
student assumes he has scored enough to pass the examination 
• Minimum attendance of 75% is mandatory to write the final exam. 
• If the student loses his book, he/she will have to rewrite all the lab details in the lab 
record. 
• Questions for lab tests and examination are not necessarily limited to the questions 
in the manual but may involve some variations and/or combinations of the questions. 
• A sample note preparation is given as a model for observation. 
 
 
THE STUDENTS SHOULD NOT 
• Bring mobile phones or any other electronic gadgets to the lab. 
• Go out of the lab without permission.


1 
 
 
LAB NO.: 1 
Date: 
 
 
 
 
Objective: 
Basic Symmetric Key Ciphers  
• To familiarize with Substitution Ciphers. 
• To understand the working of transposition ciphers. 
 
 
Introduction 
Symmetric key ciphers use the same key to encrypt and decrypt data. They are often used 
in combination with other algorithms for symmetric encryption schemes. 
 
Symmetric key cryptography schemes are categorized as stream ciphers and block ciphers. 
Stream ciphers work on a single bit (byte or computer word) at a time and execute some 
form of feedback structure so that the key is repeatedly changing. 
Figure 1: Stream Cipher 


2 
 
Block Cipher 
In a block cipher, a group of plaintext symbols of size m (m > 1) are encrypted together 
creating a group of ciphertext of the same size. A single key is used to encrypt the whole 
block even if the key is made of multiple values, as shown in Figure 2. 
 
Figure 2: Block Cipher 
A block cipher is so-called because the scheme encrypts one block of information at a time 
utilizing the same key on each block. In general, the same plaintext block will continually 
encrypt to the same ciphertext when using a similar key in a block cipher whereas the same 
plaintext will encrypt to different ciphertext in a stream cipher. 
 
Block ciphers can operate in several modes such as Electronic Codebook (ECB), Cipher 
Block Chaining (CBC), Cipher Feedback (CFB) and Output Feedback (OFB) mode.  
Substitution Ciphers 
A substitution cipher replaces one symbol with another. Substitution ciphers can be 
categorized as either monoalphabetic ciphers or polyalphabetic ciphers 


3 
In monoalphabetic substitution, the relationship between a symbol in the plaintext 
to a symbol in the ciphertext is always one-to-one.  The simplest monoalphabetic cipher is 
the additive cipher, shown in Figure 3.  This cipher is sometimes called a shift cipher and 
sometimes a Caesar cipher. 
When the cipher is additive, the plaintext, ciphertext, and key are integers in Z26.  
In a multiplicative cipher, the plaintext and ciphertext are integers in Z26; the key is 
an integer in Z26*. 
 
Figure 3. Additive Cipher 
In polyalphabetic substitution, each occurrence of a character may have a different 
substitution. The relationship between a character in the plaintext to a character in the 
ciphertext is one-to-many. 
 Auto Key Cipher 
Transposition Cipher 
A transposition cipher does not substitute one symbol for another; instead, it changes 
the location of the symbols. 


4 
• Keyless Transposition Ciphers 
• Keyed Transposition Ciphers 
• Combining Two Approaches 
 
Lab Exercises 
1. Encrypt the message "I am learning information security" using each of the following 
ciphers. Ignore the space between words. Decrypt the message to get the original plaintext: 
a) Additive cipher with key = 20 
b) Multiplicative cipher with key = 15 
c) Affine cipher with key = (15, 20) 
 
2. Encrypt the message "the house is being sold tonight" using each of the following ciphers. 
Ignore the space between words. Decrypt the message to get the original plaintext: 
a) Vigenere cipher with key: "dollars" 
b) Autokey cipher with key = 7 
 
3. Use the Playfair cipher to encipher the message "The key is hidden under the door pad". 
The secret key can be made by filling the first and part of the second row with the word 
"GUIDANCE" and filling the rest of the matrix with the rest of the alphabet. 
 
4. Use a Hill cipher to encipher the message "We live in an insecure world". Use the 
following key: 
𝐾    =  
[03 03  
02 07] 
 


5 
5. John is reading a mystery book involving cryptography. In one part of the book, the author 
gives a ciphertext "CIW" and two paragraphs later the author tells the reader that this is a 
shift cipher and the plaintext is "yes". In the next chapter, the hero found a tablet in a cave 
with "XVIEWYWI" engraved on it. John immediately found the actual meaning of the 
ciphertext.  Identify the type of attack and plaintext. 
 
6. Use a brute-force attack to decipher the following message. Assume that you know it is 
an affine cipher and that the plaintext "ab" is enciphered to "GL": 
XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS 
 
Additional Exercises 
1. Use a brute-force attack to decipher the following message enciphered by Alice using an 
additive cipher. Suppose that Alice always uses a key that is close to her birthday, which is 
on the 13th of the month: 
NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY 
 
2. Eve secretly gets access to Alice's computer and using her cipher types "abcdefghi". The 
screen shows "CABDEHFGL". If Eve knows that Alice is using a keyed transposition 
cipher, answer the following questions: 
a) What type of attack is Eve launching? 
b) What is the size of the permutation key? 
c) Use the Vigenere cipher with keyword "HEALTH" to encipher the message "Life is 
full of surprises". 
  


6 
DBS LAB MANUAL 
INTRODUCTION TO VC# AND SQL PLUS EDITOR 
vi 
LAB NO.: 2 
Date: 
 
 
 
 
Objective: 
Advanced Symmetric Key Ciphers  
• To understand the working of DES and AES algorithms.  
• To implement AES and DES algorithm.  
• Analyze the performance of AES and DES algorithms 
 
Introduction: 
DES: 
The Data Encryption Standard (DES) is a symmetric-key block cipher published by the 
National Institute of Standards and Technology (NIST) 
The encryption process is made of two permutations (P-boxes, initial and final 
permutations, and sixteen Feistel rounds as shown in Figure 4 
  
 
 
 
 
 
 


7 
Figure 4: General structure of DES  
Initial Permutation (IP): The 64-bit plaintext block is permuted according to a fixed table, 
shuffling the bits to create a new order. 
Key Schedule Generation:  The 56-bit key is divided into two 28-bit halves. Each half is 
then rotated and permuted according to a predefined schedule to produce sixteen 48-bit 
round keys, one for each round of encryption. 
16 Rounds of Encryption: The 64-bit block is split into two 32-bit halves, called Left (L) 
and Right (R). 
 
 
 
 
 
 
 
 
Figure 5: Single Round of DES Algorithm 
Single round of DES is shown in Figure 5. For each of the 16 rounds, a new right half is 
generated by expanding the previous right half to 48 bits using the Expansion (E) function. 


8 
The expanded right half is XORed with the round key. That result is passed through a 
series of substitution boxes (S-boxes), which reduce the 48-bit output back to 32 bits. The 
S-box output is then permuted using the Permutation (P) function. The new right half is 
XORed with the previous left half. The previous right half becomes the new left half. 
• After 16 rounds, the left and right halves are recombined and permuted using the 
final permutation (FP). 
Final Permutation (FP): The combined left and right halves are permuted according to a 
fixed table to produce the final 64-bit ciphertext block. 
The Advanced Encryption Standard (AES): 
AES  is a symmetric-key block cipher published by the National Institute of Standards and 
Technology (NIST) in December 2001. AES is a non-Feistel cipher that encrypts and 
decrypts a data block of 128 bits. It uses 10, 12, or 14 rounds. The key size, which can be 
128, 192, or 256 bits, depends on the number of rounds. 
Main components of AES are as follows as shown in Figure 6. 
 
 
 
 
 
Figure 6: General design of AES encryption cipher 


9 
Initial Round: AddRoundKey: Each byte of the state is combined with a round key using 
the XOR operation. 
Main Rounds (Repeated for 9, 11, or 13 times depending on key size): 
SubBytes: A non-linear substitution step where each byte is replaced with another byte 
using an S-box (substitution box). 
ShiftRows: A transposition step where each row of the state is shifted cyclically by a 
certain number of bytes. 
 
MixColumns: A mixing operation which operates on the columns of the state, combining 
the four bytes in each column. 
AddRoundKey: Each byte of the state is combined with a round key using the XOR 
operation. 
Final Round: It has SubBytes, ShiftRows and AddRoundKey steps 
 
 
 
 
 
 
Figure 7: Structure of each round at the encryption site 


10 
To provide security, AES uses four types of transformations: substitution, permutation, 
mixing, and key-adding. 
Detailed description about each type of transformation is as follows: 
Substitution 
The first transformation, SubBytes, is used at the encryption site. To substitute a byte, 
we interpret the byte as two hexadecimal digits. 
Transformation Using the GF(28) Field 
AES also defines the transformation algebraically using the GF(28) field with the 
irreducible polynomials (x8 + x4 + x3+ x + 1) 
The SubBytes and InvSubBytes transformations are inverses of each other. 
Another transformation found in a round is shifting, which permutes the bytes as shown 
in Figure 8. In the encryption, the transformation is called ShiftRows. 
   
 
 
 
 
Figure 8: ShiftRows transformation 
 


11 
InvShiftRows 
In the decryption, the transformation is called InvShiftRows and the shifting is to the 
right. 
MixColumns 
The MixColumns transformation operates at the column level; it transforms each column 
of the state to a new column. The MixColumns and InvMixColumns transformations are 
inverses of each other. 
Key Adding 
AddRoundKey proceeds one column at a time.  AddRoundKey adds a round key word 
with each state column matrix; the operation in AddRoundKey is matrix addition. 
 
Lab Exercises: 
1. Encrypt the message "Confidential Data" using DES with the following key: 
"A1B2C3D4". Then decrypt the ciphertext to verify the original message. 
2. Encrypt the message "Sensitive Information" using AES-128 with the following 
key: "0123456789ABCDEF0123456789ABCDEF". Then decrypt the ciphertext to 
verify the original message. 
3. Compare the encryption and decryption times for DES and AES-256 for the message 
"Performance Testing of Encryption Algorithms". Use a standard implementation 
and report your findings. 
4. Encrypt the message "Classified Text" using Triple DES with the key 
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF". Then decrypt 
the ciphertext to verify the original message. 


12 
5. Encrypt the message "Top Secret Data" using AES-192 with the key 
"FEDCBA9876543210FEDCBA9876543210". Show all the steps involved in the 
encryption process (key expansion, initial round, main rounds, final round). 
Additional Exercises: 
1. Using DES and AES (128, 192, and 256 bits key).encrypt the five different messages 
using same key. 
a. Consider different modes of operation 
b. Plot the graph which shows execution time taken by each technique. 
c. Compare time taken by different modes of operation 
 
2. Encrypt the following block of data using DES with the key "A1B2C3D4E5F60708". 
The data to be encrypted is: Mathematica 
Block1: 
54686973206973206120636f6e666964656e7469616c206d657373616765 
Block2: 
416e64207468697320697320746865207365636f6e6420626c6f636b 
a. Provide the ciphertext for each block. 
b. Decrypt the ciphertext to retrieve the original plaintext blocks. 
 
3. Using AES-256, encrypt the message "Encryption Strength" with the key 
"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE
F". Then decrypt the ciphertext to verify the original message. 
4. Encrypt the message "Secure Communication" using DES in Cipher Block Chaining 
(CBC) mode with the key "A1B2C3D4" and an initialization vector (IV) of "12345678". 
Provide the ciphertext and then decrypt it to retrieve the original message. 


13 
5. Encrypt the message "Cryptography Lab Exercise" using AES in Counter (CTR) mode 
with 
the 
key 
"0123456789ABCDEF0123456789ABCDEF" 
and 
a 
nonce 
of 
"0000000000000000". Provide the ciphertext and then decrypt it to retrieve the original 
message. 
 
 
 
 
 


14 
DBS LAB MANUAL 
INTRODUCTION TO VC# AND SQL PLUS EDITOR 
 
LAB NO.: 3 
Date: 
 
 
 
 
Objective: 
Asymmetric Key Ciphers  
• To demonstrate the ability to generate, use, and understand the public and private keys 
in various asymmetric encryption schemes.  
• To understand the performance implications of different asymmetric encryption 
algorithms.  
 
Introduction 
Asymmetric algorithms rely on one key for encryption and a different but related key for 
decryption. These algorithms have the following important characteristics: 
• It is computationally infeasible to determine the decryption key given only 
knowledge of cryptographic algorithms and encryption keys.  
• Either of the two related keys can be used for encryption, with the other used for 
decryption 
 
 
 
 
 
 
 


15 
 
 
 
 
 
 
 
THE RSA ALGORITHM  
The RSA scheme is a cipher in which the plaintext and ciphertext are integers between 0 
and n - 1 for some n. A typical size for n is 1024 bits, or 309 decimal digits. That is, n is 
less than 21024. We examine RSA in this section in some detail, beginning with an 
explanation of the algorithm. Then we examine some of the computational and 
cryptanalytical implications of  RSA. RSA uses the mathematical properties of prime 
numbers and modular arithmetic.  
Public keys are used for encryption, and private keys are used for decryption. The security 
of RSA relies on the difficulty of factoring large composite numbers into their prime factors. 
RSA is widely used for secure data transmission, digital signatures, and key exchange 
mechanisms due to its robustness and security features  
Key Generation  
Generate Two Large Prime Numbers: Choose two distinct large prime numbers, p and q. 
These primes should be large enough to ensure the security of the RSA algorithm.  


16 
Compute the Modulus:  
Calculate n=p×q; n is used as the modulus for both the public and private keys.  
Compute Euler's Totient Function:  Calculate ϕ(n)=(p−1)×(q−1).  
ϕ(n) represents the number of integers less than n that are relatively prime to n.  
Choose the Public Exponent: Select an integer ee such that 1<e<ϕ(n) and gcd(e,ϕ(n))=1. 
The public exponent e is typically chosen as a small prime number like 3 or 65537 for 
efficiency.  
Compute the Private Exponent: Calculate the private exponent d such that 
d×e≡1(modϕ(n)).  d is the modular multiplicative inverse of ee modulo ϕ(n).  
Public and Private Keys: The public key consists of (n,e). The private key consists of (n,d).  
Encryption  
Convert the Message: Convert the plaintext message M into an integer m such that 0≤m<n. 
This can be done using a suitable padding scheme to ensure the message is within the valid 
range.  
Encrypt the Message: Compute the ciphertext c using the public key: c=me mod  n   
Decryption  
Decrypt the Ciphertext: Compute the plaintext message m using the private key: m=cd 
mod n   
Convert the Integer Back to Message: Convert the integer m back to the original plaintext 
message M.  
ELGAMAL Encryption Algorithm  
The ElGamal encryption algorithm is an asymmetric key encryption algorithm based on the 
Diffie-Hellman key exchange. It was designed by Taher ElGamal in 1985 and provides both 
encryption and digital signature functionalities.  


17 
Key Components  
• 
Public Parameters:  
A large prime number p.  
A generator g of the multiplicative group of integers modulo p.  
Private Key: A random integer x such that 1≤x≤p−2.  
Public Key:  
Compute y=gx mod p. The public key is the tuple (p,g,y).  
Key Generation  
• Choose a large prime number p.  
• Choose a generator g for the multiplicative group of integers modulo p.  
• Select a private key x where 1≤x≤p−2  
• 
Compute the public key component y as y=gxmod  p.  
Public key: (p, g, y)  
Private key: x  
Encryption  
➢ Convert the plaintext message M into an integer m such that 0≤m<p.  
➢ Choose a random integer k such that 1≤k≤p−2.  
➢ Compute the ciphertext components:  
➢ c1=gkmod  p  
➢ c2=m⋅ykmod  p  
➢ Ciphertext: (c1 ,c2 )  
 


18 
Decryption  
➢ Use the private key x to compute: s=c1xmod  p  
➢ Compute the plaintext message m as: m=c2⋅s−1mod  p  
Here, s−1 is the modular inverse of s modulo p. Plaintext: M  
 
Elliptic Curve Cryptography (ECC)  
Elliptic Curve Cryptography (ECC) is an asymmetric encryption technique based on the 
algebraic structure of elliptic curves over finite fields. It offers significant advantages over 
traditional RSA encryption, such as smaller key sizes for equivalent security levels and 
faster computational speeds.  
Key Components  
Elliptic Curve Definition:  
An elliptic curve over a finite field Fp  is defined by an equation of the form y2=x3+ax+b 
mod p, where a and b are constants defining the curve's shape, and p is a prime number.  
Base Point G (Generator):  
A specific point on the curve used as the base for generating keys and performing 
operations.  
Private Key d:  A random integer d chosen as the private key.  
Public Key Q: The public key is computed as Q=d⋅G, where .(dot) denotes elliptic curve 
point multiplication.  
Key Generation  
Curve Parameters: Choose a suitable elliptic curve (e.g., secp256k1) defined over a finite 
field Fp . Select curve parameters a, b, and a prime modulus p.  


19 
Base Point G Selection: Choose a base point G on the elliptic curve.  
Private Key Generation: Generate a random integer d such that 1≤d<order of G.  
Public Key Computation: Compute the public key Q as Q=d⋅G.  
Public key: Q  
Private key: d  
Encryption and Decryption  
ECC is primarily used for key exchange rather than direct encryption of messages. The 
Diffie-Hellman key exchange and elliptic curve DSA (ECDSA) are commonly used 
protocols based on ECC for secure communication and digital signatures  
Lab Exercises:  
1. Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n, 
e). Then decrypt the ciphertext with the private key (n, d) to verify the original 
message.  
2. Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure 
Transactions" with the public key. Then decrypt the ciphertext with the private key 
to verify the original message.  
3. Given an ElGamal encryption scheme with a public key (p, g, h) and a private key 
x, encrypt the message "Confidential Data". Then decrypt the ciphertext to retrieve 
the original message.  
4. Design and implement a secure file transfer system using RSA (2048-bit) and ECC 
(secp256r1 curve) public key algorithms. Generate and exchange keys, then encrypt 
and decrypt files of varying sizes (e.g., 1 MB, 10 MB) using both algorithms. 
Measure and compare the performance in terms of key generation time, 
encryption/decryption speed, and computational overhead. Evaluate the security and 
efficiency of each algorithm in the context of file transfer, considering factors such 


20 
as key size, storage requirements, and resistance to known attacks. Document your 
findings, including performance metrics and a summary of the strengths and 
weaknesses of RSA and ECC for secure file transfer.  
5. As part of a project to enhance the security of communication in a peer-to-peer file 
sharing system, you are tasked with implementing a secure key exchange 
mechanism using the Diffie-Hellman algorithm. Each peer must establish a shared 
secret key with another peer over an insecure channel. Implement the Diffie-
Hellman key exchange protocol, enabling peers to generate their public and private 
keys and securely compute the shared secret key. Measure the time taken for key 
generation and key exchange processes.  
Additional Exercises:  
1. With the ElGamal public key (p = 7919, g = 2, h = 6465) and the private key x = 
2999, encrypt the message "Asymmetric Algorithms". Decrypt the resulting 
ciphertext to verify the original message.  
2. Using ECC (Elliptic Curve Cryptography), encrypt the message "Secure 
Transactions" with the public key. Then decrypt the ciphertext with the private key 
to verify the original message.  
3. Encrypt the message "Cryptographic Protocols" using the RSA public key (n, e) 
where n = 323 and e = 5. Decrypt the ciphertext with the private key (n, d) where d 
= 173 to confirm the original message  
4. You are tasked with implementing a secure communication system for a healthcare 
organization to exchange sensitive patient information securely between doctors and 
hospitals. Implement the ElGamal encryption scheme to encrypt patient records and 
medical data, ensuring confidentiality during transmission. Generate public and 
private keys using the secp256r1 curve and use ElGamal encryption to encrypt 
patient data with the recipient's public key and decrypt it with the recipient's private 


21 
key. Measure the performance of encryption and decryption processes for data of 
varying sizes.  
5. You are conducting a study to evaluate the performance and security of RSA and 
ElGamal encryption algorithms in securing communication for a government 
agency. Implement both RSA (using 2048-bit keys) and ElGamal (using the 
secp256r1 curve) encryption schemes to encrypt and decrypt sensitive messages 
exchanged between agencies. Measure the time taken for key generation, 
encryption, and decryption processes for messages of various sizes (e.g., 1 KB, 10 
KB). Compare the computational efficiency and overhead of RSA and ElGamal 
algorithms. Perform the same for ECC with RSA and ElGamal.  
  
 
  


22 
DBS LAB MANUAL 
INTRODUCTION TO VC# AND SQL PLUS EDITOR 
vi 
LAB NO.: 4 
Date: 
 
 
 
 
Objective: 
Advanced Asymmetric Key Ciphers  
 
• Implement and compare the performance of multiple asymmetric encryption 
algorithms (e.g., RSA, ElGamal, Rabin) in a controlled environment, measuring 
factors such as encryption/decryption speed and key generation time.  
• Design and develop a modular key management system capable of handling 
various cryptographic protocols, with emphasis on scalability, security, and ease 
of integration.  
• Create a flexible framework for testing different access control mechanisms in 
cryptographic systems, allowing for easy implementation and evaluation of 
various policies and revocation strategies  
 
Introduction 
Asymmetric Encryption Algorithms: Asymmetric encryption, also known as public-key 
cryptography, uses a pair of mathematically related keys: a public key for encryption and 
a private key for decryption. This approach allows secure communication without the need 
to share secret keys. Common asymmetric algorithms include RSA, ElGamal, and Rabin. 
Each has its own mathematical foundations and security properties, making comparative 
analysis valuable for understanding their strengths and weaknesses in different scenarios.  
 
Key Management Systems: Key management is a critical aspect of cryptographic 
systems, encompassing the generation, exchange, storage, use, and replacement of 
cryptographic keys. A robust key management system ensures the security and integrity 
of encrypted communications. It must handle tasks such as key generation, distribution, 
storage, rotation, and revocation. The challenges in key management increase with the 


23 
scale and complexity of the system, especially in distributed environments.  
 
Access Control in Cryptographic Systems: Access control in cryptography involves 
mechanisms to restrict access to encrypted data or cryptographic operations. This includes 
managing who can encrypt or decrypt data, as well as controlling access to keys. 
Implementing flexible access control policies is crucial for maintaining security in various 
scenarios, from simple user authentication to complex, attribute-based access control 
systems. The ability to revoke access and update policies dynamically is also an important 
consideration in modern cryptographic systems.  
 
Mathematical Foundations  
RSA Algorithm:  
1. Key Generation:  
   - Choose two large prime numbers p and q  
   - Compute n = p * q  
   - Compute φ(n) = (p-1) * (q-1)  
   - Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1  
   - Compute d such that d * e ≡ 1 (mod φ(n))  
   - Public key: (n, e), Private key: (n, d)  
 
 2. Encryption:   
   For plaintext m, ciphertext c = m^e mod n  
 
3. Decryption:   
   m = c^d mod n  
 
ElGamal Algorithm:  
1. Key Generation:  


24 
   - Choose a large prime p and a generator g of the multiplicative group of integers modulo 
p  
   - Choose a random integer x, 1 < x < p-1  
   - Compute y = g^x mod p  
   - Public key: (p, g, y), Private key: x  
 
2. Encryption:  
   - Choose a random k, 1 < k < p-1  
   - Compute c1 = g^k mod p  
   - Compute s = y^k mod p  
   - For plaintext m, compute c2 = m * s mod p  
   - Ciphertext: (c1, c2)  
 
3. Decryption:  
   - Compute s = c1^x mod p  
   - Compute m = c2 * s^(-1) mod p  
 
Rabin Algorithm:  
1. Key Generation:  
   - Choose two large primes p and q, where p ≡ q ≡ 3 (mod 4)  
   - Compute n = p * q  
   - Public key: n, Private key: (p, q)  
 
2. Encryption:  
   For plaintext m, ciphertext c = m^2 mod n  
 
3.Decryption:  
   - Compute mp = c^((p+1)/4) mod p  


25 
   - Compute mq = c^((q+1)/4) mod q  
   - Use Chinese Remainder Theorem to find four square roots:  
 
     r1 = (yp * p * mq + yq * q * mp) mod n  
     r2 = n - r1  
     r3 = (yp * p * mq - yq * q * mp) mod n  
     r4 = n - r3  
   where yp * p + yq * q = 1  
   - One of these roots is the original message m  
Each of these algorithms has its own unique mathematical properties that contribute to its 
security and performance characteristics. RSA relies on the difficulty of factoring large 
numbers, ElGamal is based on the discrete logarithm problem, and Rabin's security is tied 
to the difficulty of finding square roots modulo a composite number.  
 
Key Management Systems:  
1. Key Entropy:  
   Entropy H of a key K with n possible values, each with probability p(i):  
   H(K) = -∑(i=1 to n) p(i) * log2(p(i))  
2. Key Derivation Function (KDF):  
   DK = KDF(Key, Salt, Iterations)  
   Where DK is the derived key, Key is the original key or password, Salt is a random 
value,  and Iterations is the number of times the function is applied.  
3. Key Rotation:  
   For a system with N keys and a rotation period of T:  
   Rotation Rate = N / T  
4. Key Expiry:  
   If a key K is created at time t0 with lifetime L:  
   Expiry Time = t0 + L  


26 
5. Diffie-Hellman Key Exchange:  
   Public parameters: prime p, generator g  
   Alice computes: A = g^a mod p  
   Bob computes: B = g^b mod p  
   Shared secret: K = A^b mod p = B^a mod p = g^(ab) mod p  
  
Access Control in Cryptographic Systems:  
1. Role-Based Access Control (RBAC):  
   Access(User, Object) = ∃Role : HasRole(User, Role) ∧ CanAccess(Role, Object)  
2. Attribute-Based Access Control (ABAC):  
 Access(User, 
Object, 
Environment) 
= 
f(UserAttributes, 
ObjectAttributes, 
EnvironmentAttributes)  
   Where f is a policy function evaluating to true or false.  
3. Bell-LaPadula Model:  
   - Simple Security Property: S(Subject) ≥ C(Object) for read access  
   - *-Property: S(Subject) ≤ C(Object) for write access  
4. Mandatory Access Control (MAC): 
 AccessGranted = (SubjectClearance ≥ ObjectClassification) ∧ 
PolicyRulesatisfied 
5. Discretionary Access Control (DAC): 
 AccessMatrix[Subject, Object] = {Rights} 
Where Rights could be Read, Write, Execute, etc. 
6. Time-based Access Control 
Access (User, Object, Time) = (Time ≥ StartTime) ∧ (Time ≤ EndTime) ∧ 
OtherConditions 
7. Probabilistic Access Control: 
 P(Access Granted | Conditions) = f(UserTrustLevel, ObjectSensitivity,  
EnvironmentRisk) 


27 
 Where P is probability and f is a function mapping conditions to a probability. 
These equations and mathematical concepts form the basis for implementing and 
analyzing key management and access control systems. They allow for quantitative 
assessment of security properties, guide the design of secure systems, and provide a 
framework for evaluating the effectiveness of different approaches in cryptographic access 
control. 
 
Lab exercises 
Question 1 
SecureCorp is a large enterprise with multiple subsidiaries and business units located 
across different geographical regions. As part of their digital transformation initiative, the 
IT team at SecureCorp has been tasked with building a secure and scalable communication 
system to enable seamless collaboration and information sharing between their various 
subsystems. 
The enterprise system consists of the following key subsystems: 
1. Finance System (System A): Responsible for all financial record-keeping, accounting, 
and reporting. 
2. HR System (System B): Manages employee data, payroll, and personnel related 
processes. 
3. Supply Chain Management (System C): Coordinates the flow of goods, services, and 
information across the organization's supply chain 
These subsystems need to communicate securely and exchange critical documents, such 
financial reports, employee contracts, and procurement orders, to ensure the enterprise's 
overall efficiency. 
The IT team at SecureCorp has identified the following requirements for the secure 
communication and document signing solution: 
1. Secure Communication: The subsystems must be able to establish secure 
communication channels using a combination of RSA encryption and Diffie-Hellman key 


28 
exchange. 
2. Key Management: SecureCorp requires a robust key management system to generate, 
distribute, and revoke keys as needed to maintain the security of the enterprise system. 
3. Scalability: The solution must be designed to accommodate the addition of new 
subsystems in the future as SecureCorp continues to grow and expand its operations. 
Implement a Python program which incorporates the requirements. 
 
Question 2: 
HealthCare Inc., a leading healthcare provider, has implemented a secure patient data 
management system using the Rabin cryptosystem. The system allows authorized 
healthcare professionals to securely access and manage patient records across multiple 
hospitals and clinics within the organization. Implement a Python-based centralized key 
management service that can: 
• Key Generation: Generate public and private key pairs for each hospital and clinic using 
the Rabin cryptosystem. The key size should be configurable (e.g., 1024 bits). 
• Key Distribution: Provide a secure API for hospitals and clinics to request and receive 
their public and private key pairs. 
• Key Revocation: Implement a process to revoke and update the keys of a hospital or 
clinic when necessary (e.g., when a facility is closed or compromised). 
• Key Renewal: Automatically renew the keys of all hospitals and clinics at regular 
intervals (e.g., every 12 months) to maintain the security of the patient data management 
system. 
• Secure Storage: Securely store the private keys of all hospitals and clinics, ensuring that 
they are not accessible to unauthorized parties. 
• Auditing and Logging: Maintain detailed logs of all key management operations, such 
as key generation, distribution, revocation, and renewal, to enable auditing and compliance 
reporting. 
• Regulatory Compliance: Ensure that the key management service and its operations are 


29 
compliant with relevant data privacy regulations (e.g., HIPAA). 
• Perform a trade-off analysis to compare the workings of Rabin and RSA.  
 
Additional Questions 
Question 1 
DigiRights Inc. is a leading provider of digital content, including e-books, movies, and 
music. The company has implemented a secure digital rights management (DRM) system 
using the ElGamal cryptosystem to protect its valuable digital assets.  
Implement a Python-based centralized key management and access control service that 
can: 
• Key Generation: Generate a master public-private key pair using the ElGamal 
cryptosystem. The key size should be configurable (e.g., 2048 bits). 
• Content Encryption: Provide an API for content creators to upload their digital content 
and have it encrypted using the master public key. 
• Key Distribution: Manage the distribution of the master private key to authorized 
customers, allowing them to decrypt the content. 
• Access Control: Implement flexible access control mechanisms, such as:  
◼ Granting limited-time access to customers for specific content 
◼ Revoking access to customers for specific content 
◼ Allowing content creators to manage access to their own content 
• Key Revocation: Implement a process to revoke the master private key in case of a 
security breach or other emergency. 
• Key Renewal: Automatically renew the master public-private key pair at regular intervals 
(e.g., every 24 months) to maintain the security of the DRM system. 
• Secure Storage: Securely store the master private key, ensuring that it is not accessible 
to unauthorized parties. 
• Auditing and Logging: Maintain detailed logs of all key management and access control 
operations to enable auditing and troubleshooting. 


30 
Question 2  
Suppose that XYZ Logistics has decided to use the RSA cryptosystem to secure their 
sensitive communications. However, the security team at XYZ Logistics has discovered 
that one of their employees, Eve, has obtained a partial copy of the RSA private key and 
is attempting to recover the full private key to decrypt the company's communications. 
Eve's attack involves exploiting a vulnerability in the RSA key generation process, where 
the prime factors (p and q) used to generate the modulus (n) are not sufficiently large or 
random. 
Develop a Python script that can demonstrate the attack on the vulnerable RSA 
cryptosystem and discuss the steps to mitigate the attack. 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 


31 
DBS LAB MANUAL 
INTRODUCTION TO VC# AND SQL PLUS EDITOR 
vi 
LAB NO.: 5 
Date: 
 
 
 
 
Objective: 
                     Hashing  
 
• To implement user defined hashing function. 
• To demonstrate the application of hash function. 
 
Introduction 
A hash function H takes an input data block M of variable length and generates a fixed-
size hash value h=H(M). An effective hash function ensures that applying it to a large set 
of inputs yields outputs that are evenly distributed and seemingly random. The primary 
goal of a hash function is to maintain data integrity, such that any change in the input M, 
even by a single bit, will likely result in a different hash value. For security purposes, a 
special type of hash function, known as a cryptographic hash function, is used. This 
algorithm has two key properties: 
• The one-way property, which makes it computationally infeasible to find a data object 
that matches a pre-specified hash result. 
• The collision-free property, which makes it computationally infeasible to find two 
distinct data objects that produce the same hash result. 
Due to these properties, cryptographic hash functions are commonly employed to  
verify whether data has been altered. 
Figure 5.1 illustrates how a cryptographic hash function operates. Generally, the input data 
is padded to make its length an integer multiple of a specific fixed size (e.g., 1024 bits). 
This padding includes a field that represents the length of the original message in bits. The 
length field acts as a security measure, making it more challenging for an attacker to create 
a different message with the same hash value. [Ref: Cryptography  


32 
and Network Security: Principles and Practice 7th Global Edition] 
 
 
 
 
 
 
 
 
 
Figure 5.1 Cryptographic Hash Function 
 
Lab Exercises 
1. Implement the hash function in Python. Your function should start with an initial hash 
value of 5381 and for each character in the input string, multiply the current hash value by 
33, add the ASCII value of the character, and use bitwise operations to ensure thorough 
mixing of the bits. Finally, ensure the hash value is kept within a 32-bit range by applying 
an appropriate mask. 
2. Using socket programming in Python, demonstrate the application of hash functions for 
ensuring data integrity during transmission over a network. Write server and client scripts 
where the server computes the hash of received data and sends it back to the client, which 
then verifies the integrity of the data by comparing the received hash with the locally 
computed hash. Show how the hash verification detects data corruption  
or tampering during transmission. 
3. Design a Python-based experiment to analyze the performance of MD5, SHA-1, and 
SHA-256 hashing techniques in terms of computation time and collision resistance. 
Generate a dataset of random strings ranging from 50 to 100 strings, compute the hash 
values using each hashing technique, and measure the time taken for hash computation. 


33 
Implement collision detection algorithms to identify any collisions within the hashed 
dataset. 
  
Additional Exercise 
1. Write server and client scripts where the client sends a message in multiple parts to the 
server, the server reassembles the message, computes the hash of the reassembled 
message, and sends this hash back to the client. The client then verifies the integrity of the 
message by comparing the received hash with the locally computed hash of the original 
message. 
 
 
 


34 
DBS LAB MANUAL 
INTRODUCTION TO VC# AND SQL PLUS EDITOR 
vi 
LAB NO.: 6 
Date: 
 
 
 
 
Objective: 
       Digital Signature  
 
• Demonstrate the use of digital signatures 
• Demonstrate the verification of a digital signature 
 
Introduction 
A digital signature is a mathematical technique used to validate the authenticity and 
integrity of a digital message. A digital signature is the equivalent of a handwritten 
signature. Digital signatures can actually be far more secure. The purpose of a digital 
signature is to prevent the tampering and impersonation in digital communications.  
Using Digital Signatures  
In this part, you will use a website to verify a document signature between Alice and Bob. 
Alice and Bob share a pair of private and public RSA keys. Each of them uses their private 
key to sign a legal document. They then send the documents to each other. Both Alice and 
Bob can verify each other’s signature with the public key. They must also agree on a 
shared public exponent for calculation 
Table 1 – RSA Public and Private Keys 


35 
 
Step 1: Sign the Document. 
Alice signs a legal document and send it to Bob using the RSA public and private keys 
shown in the table 1. Now Bob will have to verify Alice’s digital signature in order to trust 
the authenticity of the electronic document. 
Step 2: Verify Digital Signature. 
Bob receives the document with a digital signature shown in the table below. 
Table 2 – Alice’s Digital Signature 
 
a. Copy and paste the public and private keys from Table 1 above into the Public Modulus 
and Private Exponent boxes on the website as shown in the Figure 6.1. 
b. Make sure the Public Exponent is 10001. 
c. Paste Alice’s digital signature from Table 2 in the box labeled text on the website as 


36 
shown. 
d. Now BOB can verify the digital signature by clicking the Verify button near the bottom 
center of the website. Whose signature is identified? 
Alice’s name should be displayed. 
Step 3: Generate a Response Signature. 
Bob receives and verifies Alice’s electronic document and digital signature. Now Bob 
creates an electronic document and generates his own digital signature using the private 
RSA Key in Table 1 (Note: Bob’s name is in all capital letters). 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
Figure 6.1 Online Digital Signature Tool 
 
Table 4 – BOB Digital Signature 


37 
 
 
 
 
 
 
 
 
Bob sends the electronic document and digital signature to Alice. 
Step 4: Verify Digital Signature. 
a. Copy and paste the public and private keys from Table 1 above into the Public Modulus 
and Private Exponent boxes on the website as shown in the picture above. 
b. Make sure the Public Exponent is 10001. 
c. Paste Bob’s digital signature from Table 4 in the box labeled text on the website as 
shown above. 
d. Now Alice can verify the digital signature by clicking the Verify button near the bottom 
center of the website. Whose signature is identified? 
Bob’s name should be displayed. 
Part 2: Create Your Own Digital Signature 
Now that you see how digital signatures work, you can create your own digital signature. 
Step 1: Generate a New Pair of RSA Keys. 
Go to the website tool and generate a new set of RSA public and private keys. 
a. Delete the contents of the boxes labeled Public Modulus, Private Modulus and Text. 
Just use your mouse to highlight the text and press the delete key on your keyboard. 
b. Make sure the “Public Exponent” box has 10001. 
c. Generate a new set of RSA keys by clicking the Generate button near the bottom right 
of the website. 
d. Copy the new keys in Table  5. 


38 
 
 
 
 
 
e. Now type in your full name into the box labeled Text and click Sign. 
 
 
 
 
 
 
Part 3: Exchange and Verify Digital Signatures 
Now you can use this digital signature. 
Step 1: Exchange your new public and private keys in Table-5 with your lab partner. 
a. Record your lab partner’s public and private RSA keys from their Table-5. 
b. Record both keys in the table below. 
 Now exchange their digital signature from their Table-6. Record the digital signature in 
the table below 
 
 
 


39 
 
Step 2: Verify Lab Partners Digital Signature 
a. To verify your lab partner’s digital signature, paste his or her public and private keys in 
the appropriate boxes labeled Public and Private modulus on the website. 
b. Now paste the digital signature in the box labeled Text. 
c. Now verify his or her digital signature by clicking the button labeled verify. 
d. What shows up in the Text box? 
Answers will vary. 
Lab Exercises 
1. Try using the Elgammal, Schnor asymmetric encryption standard and verify the above 
steps.  
2. Try using the Diffie-Hellman asymmetric encryption standard and verify the above 
steps. 
3. Try the same in a client server-based scenario and record your observation and analysis. 
 
Additional Exercise 
1. Explore the link https://www.nmichaels.org/rsa.py for better understanding. 
Demonstrate CIA traid using RSA encryption and digital signature along with SHA 
hashing. 
 
 
 
 
 


40 
DBS LAB MANUAL 
INTRODUCTION TO VC# AND SQL PLUS EDITOR 
vi 
LAB NO.: 7 
Date: 
 
 
 
 
Objective: 
Partial Homomorphic Encryption  
• Implement and Understand Additive Homomorphic Encryption 
• Implement and Understand Multiplicative Homomorphic Encryption 
• Evaluate and Apply Partial Homomorphic Encryption 
 
Introduction to Homomorphic Encryption 
Homomorphic encryption allows computations on encrypted data without decryption. 
This  
enables secure analysis of sensitive information while preserving privacy. There are two 
main types of HE: 
• Partially Homomorphic Encryption (PHE): Supports either addition or 
multiplication homomorphically. 
• Fully Homomorphic Encryption (FHE): Supports both addition and multiplication 
homomorphically. 
Partially Homomorphic Encryption (PHE) 
PHE allows performing either addition or multiplication on encrypted data. Some evident 
PHE schemes include Paillier and ElGamal. 
Homomorphic Addition (Paillier Cryptosystem) 
This exercise demonstrates homomorphic addition using the Paillier Cryptosystem.  
Problem: Add two encrypted integers (a and b). 
This program demonstrates how to perform homomorphic addition on encrypted integers  
using the Paillier Cryptosystem. 
Key functionalities and Explanations: 
• generate_keypair: Generates a public/private key pair for encryption and decryption. 


41 
• encrypt: Encrypts a message (integer) using the public key and random blinding for 
security. 
• decrypt: Decrypts a ciphertext using the private key (optional, for demonstration 
only). 
• homomorphic_add: Performs homomorphic addition on two encrypted messages.  
This works because multiplying encrypted messages under Paillier corresponds to adding 
the original messages. 
Python Code: 
from Crypto.PublicKey import RSA 
from Crypto.Random import get_random_bytes 
 
def generate_keypair(nlength=1024): 
 """Generates a public/private key pair""" 
 key = RSA.generate(nlength) 
 pub_key = key.publickey() 
 return pub_key, key 
 
def encrypt(pub_key, message): 
 """Encrypts a message using the public key""" 
 random_bytes = get_random_bytes(16) 
 p, q = pub_key.n // 2, pub_key.n // 2 + 1 
 while math.gcd(p, q) != 1: 
 p, q = pub_key.n // 2, pub_key.n // 2 + 1 
 m_dot = pow(message, 2, pub_key.n) 
 r_dot = pow(int.from_bytes(random_bytes, byteorder='big'), 2, pub_key.n) 
 ciphertext = m_dot * r_dot % pub_key.n 
 return ciphertext 
 


42 
def decrypt(priv_key, ciphertext): 
 """Decrypts a ciphertext using the private key""" 
 p = priv_key.n // 2  
 l = (ciphertext - 1) // pub_key.n 
 message = math.floor(l * pow(p, -1, priv_key.n)) 
 return message 
 
def homomorphic_add(ciphertext1, ciphertext2, pub_key): 
 """Performs homomorphic addition on ciphertexts""" 
 return ciphertext1 * ciphertext2 % pub_key.n 
 
# Generate key pair 
pub_key, priv_key = generate_keypair() 
 
# Encrypt integers 
a = 5 
b = 10 
ciphertext_a = encrypt(pub_key, a) 
ciphertext_b = encrypt(pub_key, b) 
 
# Homomorphic addition 
ciphertext_sum = homomorphic_add(ciphertext_a, ciphertext_b, pub_key) 
 
# Decrypt the sum (optional) 
# decrypted_sum = decrypt(priv_key, ciphertext_sum) 
# print(f"Decrypted sum: {decrypted_sum}") 
print(f"Ciphertext of a: {ciphertext_a}") 
print(f"Ciphertext of b: {ciphertext_b}") 


43 
print(f"Ciphertext of a + b: {ciphertext_sum}" 
 
 
Secure Medical Diagnosis (ElGamal Cryptosystem) 
Explanation: 
ElGamal uses a public key for encryption and a private key for decryption.  
encrypt creates a random blinding factor and encrypts the message.  
homomorphic_comparison multiplies ciphertexts with additional manipulation to achieve 
encrypted comparison (>). 
Decrypting the comparison result (optional) reveals if the first message was greater than 
the second. 
The diagnosis is made based on the decrypted comparison result (demonstration only, not 
recommended in practice). 
 
Problem: Perform a secure diagnosis on encrypted patient data (blood pressure). 
• A doctor wants to diagnose patients with high blood pressure (> 130) without decrypting 
their actual blood pressure readings. 
• Use ElGamal encryption, which supports homomorphic comparison. 
 
Python Code: 
from Crypto.Util.Padding import pad, unpad 
from Crypto.Random import get_random_bytes 
 
def generate_keypair(p=1024): 
 """Generates a public/private key pair""" 
 while True: 
 x = int.from_bytes(get_random_bytes(p // 8), byteorder='big') 
 if pow(2, p - 1, p) == 1 and 1 < x < p-1: 


44 
 break 
 g = 2 
 y = pow(g, x, p) 
 return ((p, g, y), x) # Public key, private key 
 
def encrypt(pub_key, message): 
 """Encrypts a message using the public key""" 
 p, g, y = pub_key 
 r = int.from_bytes(get_random_bytes(p // 8), byteorder='big') 
 while math.gcd(r, p) != 1: 
 r = int.from_bytes(get_random_bytes(p // 8), byteorder='big') 
 a = pow(g, r, p) 
 b = (message * pow(y, r, p)) % p 
 return (a, b) 
 
def decrypt(priv_key, ciphertext): 
 """Decrypts a ciphertext using the private key""" 
 p, g, _ = priv_key 
 a, b = ciphertext 
 x = priv_key 
 message = (b * pow(a, -x, p)) % p 
 return message 
 
def homomorphic_comparison(ciphertext1, ciphertext2, pub_key): 
 """Performs homomorphic comparison on ciphertexts (greater than)""" 
 p, g, y = pub_key 
 a1, b1 = ciphertext1 
 a2, b2 = ciphertext2 


45 
 return (a1 * a2) % p, (b1 * b2 * pow(y, 1, p)) % p # Encrypted result (m1 > m2 
 
# Generate key pair 
pub_key, priv_key = generate_keypair() 
 
# Blood pressure readings (already encrypted) 
blood_pressure1 = encrypt(pub_key, 120) 
blood_pressure2 = encrypt(pub_key, 140) 
 
# Homomorphic comparison (encrypted result) 
ciphertext_comparison = homomorphic_comparison(blood_pressure1, blood_pressure2,  
pub_key) 
# Decrypt the comparison result (optional - for demonstration only) 
# decrypted_comparison = decrypt(priv_key, ciphertext_comparison) 
# print(f"Decrypted comparison: {decrypted_comparison} (True if blood pressure 1 > 
blood pressure 2)") 
# Diagnosis based on the encrypted comparison result 
diagnosis = ciphertext_comparison[0] * pow(ciphertext_comparison[1], -1, pub_key[0]) 
%  
pub_key[0] 
if diagnosis > 1: 
 print("Diagnosis: High Blood Pressure detected.") 
else: 
 print("Diagnosis: Normal Blood Pressure.") 
 
Key functionalities: 
• generate_keypair: Generates a public/private key pair for ElGamal encryption. 
• encrypt: Encrypts a message (blood pressure reading) using the public key and a random 


46 
factor. 
• homomorphic_comparison: Performs homomorphic comparison on two encrypted 
messages. This leverages ElGamal's properties to create an encrypted result indicating if 
one message is greater than the other. 
• decrypt (not recommended): While included for demonstration, decrypting the 
comparison result in a real-world scenario would reveal sensitive information. Diagnosis 
should rely on the encrypted comparison itself. 
• Explore additional libraries like PALISADE (https://palisade-crypto.org/) for more  
advanced PHE functionalities 
 
Lab Exercises 
1. Implement the Paillier encryption scheme in Python. Encrypt two integers (e.g., 15 and 
25) using your implementation of the Paillier encryption scheme. Print the ciphertexts. 
Perform an addition operation on the encrypted integers without decrypting them. Print 
the result of the addition in encrypted form. Decrypt the result of the addition and verify 
that it matches the sum of the original integers. 
2. Utilize the multiplicative homomorphic property of RSA encryption. Implement a basic 
RSA encryption scheme in Python. Encrypt two integers (e.g., 7 and 3) using your 
implementation of the RSA encryption scheme. Print the ciphertexts. Perform a 
multiplication operation on the encrypted integers without decrypting them. Print the 
result of the multiplication in encrypted form. Decrypt the result of the multiplication and 
verify that it matches the product of the original integers. 
 
Additional Questions 
Implement similar exercise for other PHE operations (like homomorphic multiplication 
using ElGamal) or explore different functionalities within Paillier. 
1a: Homomorphic Multiplication (ElGamal Cryptosystem): Implement ElGamal 
encryption and demonstrate homomorphic multiplication on encrypted messages. 


47 
(ElGamal supports multiplication but not homomorphic addition.) 
1b: Secure Data Sharing (Paillier): Simulate a scenario where two parties share 
encrypted data and perform calculations on the combined data without decryption. 
1c: Secure Thresholding (PHE): Explore how PHE can be used for secure multi-party 
computation, where a certain number of parties need to collaborate on a computation 
without revealing their individual data. 
1d: Performance Analysis (Benchmarking): Compare the performance of different PHE 
schemes (Paillier and ElGamal) for various operations 
 
 
 
 
 
 
 
 
 
 
 
 
 
 


48 
DBS LAB MANUAL 
INTRODUCTION TO VC# AND SQL PLUS EDITOR 
vi 
LAB NO.: 8 
Date: 
 
 
 
 
Objective: 
Searchable Encryption  
• Understand the Fundamentals of Searchable Encryption (SE) 
• Implement and Perform Encrypted Data Searches 
• Analyze the Security and Efficiency Trade-offs 
 
Searchable encryption (SE) 
It is a cryptographic technique that enables efficient search operations on encrypted data 
without compromising its confidentiality. This paradigm is essential in modern data 
management, where data privacy and utility are often conflicting objectives. SE offers a 
solution by allowing authorized users to search for specific information within encrypted 
datasets without revealing any underlying data. 
Core Concepts used in the SE 
• Encryption: The foundational layer, where data is transformed into an unreadable 
format using cryptographic algorithms. Standard symmetric or asymmetric 
encryption techniques can be employed.  
• Indexing: A crucial component for enabling search. Data is indexed using 
cryptographic  primitives to generate searchable representations, often termed 
"encrypted indexes." These indexes must allow for efficient search operations 
without exposing the underlying data. 
• Query Processing: When a search query is issued, it is encrypted and compared 
against  the encrypted indexes. Matching results are identified, and their encrypted 
locations or identifiers are returned. The actual data remains encrypted until 
accessed by an authorized user with the decryption key. 
 


49 
 
 
Categories of S 
Symmetric Searchable Encryption (SSE) is a cryptographic primitive designed to 
reconcile the  conflicting objectives of data confidentiality and searchability. In SSE, a 
shared secret key is employed to encrypt data and construct searchable indexes. This 
approach enables authorized parties to perform search operations over encrypted data 
without compromising the underlying information. While SSE offers advantages in terms 
of efficiency compared to its public-key counterpart, it necessitates careful design to 
prevent information leakage through the search process and address challenges related to 
key management and distribution. 
Major Points 
• SSE employs a shared secret key for both encryption and decryption.  
• SSE offers relatively efficient search performance but suffers from crucial management  
challenges. 
• Some of the SSE schemes include the Boneh-Goh-Nissim (BGN) and the Cuccioletta-
Damiani-Di-Crescenzo (CDD) schemes. 
 
Public-key searchable Encryption (PKSE) is a cryptographic technique that enables 
search operations on encrypted data while maintaining data confidentiality using 
asymmetric cryptography. Unlike Symmetric Searchable Encryption (SSE), PKSE 
employs a public-key/private-key pair for encryption and decryption. PKSE allows for 
flexible access control, as multiple users can encrypt data using the public key, while only 
the holder of the corresponding private key can decrypt and search the data. PKSE offers 
greater flexibility in key management than SSE but often incurs higher computational 
overhead due to public-key operations. 
Major Points 
• PKSE uses public-key cryptography, where data is encrypted using a public key and  


50 
decrypted with the corresponding private key.  
• PKSE provides greater flexibility in key management and access control. 
• Typically, less efficient than SSE due to the computational overhead of public-key 
operations. 
 
SSE sample code 
import random 
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes 
from Crypto.Util.Padding import pad, unpad 
import hashlib 
 
def encrypt_data(key, data): 
 cipher = AES.new(key, AES.MODE_CBC) 
 iv = cipher.iv 
 ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size)) 
 return iv, ciphertext 
 
def decrypt_data(key, iv, ciphertext): 
 cipher = AES.new(key, AES.MODE_CBC, iv) 
 plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size) 
 return plaintext.decode() 
 
def create_index(documents, key): 
 index = {} 
 for doc_id, doc in documents.items(): 
 for word in doc.split(): 
 word_hash = hashlib.sha256(word.encode()).digest() 


51 
 if word_hash not in index: 
 index[word_hash] = [] 
 index[word_hash].append(doc_id) 
 # Encrypt the index 
 encrypted_index = {} 
 for word_hash, doc_ids in index.items(): 
 encrypted_index[encrypt_data(key, word_hash)[1]] = [encrypt_data(key, str(doc_id))[1] 
for doc_id in doc_ids] 
 return encrypted_index 
 
def search(encrypted_index, query, key): 
 query_hash = hashlib.sha256(query.encode()).digest() 
 encrypted_query_hash = encrypt_data(key, query_hash)[1] 
 if encrypted_query_hash in encrypted_index: 
 return [decrypt_data(key, *encrypt_data(key, doc_id))[0] for doc_id in 
encrypted_index[encrypted_query_hash]] 
 else: 
 return [] 
 
# Example usage 
documents = { 
 "doc1": "this is a document with some words", 
 "doc2": "another document with different words", 
 "doc3": "yet another document with some common words" 
} 
key = get_random_bytes(16) 
encrypted_index = create_index(documents, key) 
query = "document" 


52 
results = search(encrypted_index, query, key) 
print(results) 
PKSE Sample Code: 
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP 
from Crypto.Hash import SHA256 
import random 
 
def generate_keys(): 
keyPair = RSA.generate(2048) 
pubKey = keyPair.publickey() 
privKey = keyPair 
return pubKey, privKey 
 
def encrypt_data(pubKey, data): 
cipher = PKCS1_OAEP.new(pubKey) 
ciphertext = cipher.encrypt(data.encode()) 
return ciphertext 
 
def decrypt_data(privKey, ciphertext): 
cipher = PKCS1_OAEP.new(privKey) 
plaintext = cipher.decrypt(ciphertext) 
return plaintext.decode() 
 
def create_index(documents, pubKey): 
index = {} 
for doc_id, doc in documents.items(): 
for word in doc.split(): 


53 
word_hash = SHA256.new(word.encode()).digest() 
if word_hash not in index: 
index[word_hash] = [] 
index[word_hash].append(doc_id) 
 
# Encrypt the index 
encrypted_index = {} 
for word_hash, doc_ids in index.items(): 
encrypted_index[encrypt_data(pubKey, 
word_hash)] 
= 
[encrypt_data(pubKey, 
str(doc_id)) 
for doc_id in doc_ids] 
return encrypted_index 
 
def search(encrypted_index, query, pubKey, privKey): 
query_hash = SHA256.new(query.encode()).digest() 
encrypted_query_hash = encrypt_data(pubKey, query_hash) 
if encrypted_query_hash in encrypted_index: 
encrypted_doc_ids = encrypted_index[encrypted_query_hash] 
doc_ids = [decrypt_data(privKey, doc_id) for doc_id in encrypted_doc_ids] 
return doc_ids 
else: 
return [] 
 
# Example usage 
documents = { 
"doc1": "this is a document with some words", 
"doc2": "another document with different words", 
"doc3": "yet another document with some common words" 


54 
} 
 
pubKey, privKey = generate_keys() 
encrypted_index = create_index(documents, pubKey) 
query = "document" 
results = search(encrypted_index, query, pubKey, privKey) 
print(results) 
 
Lab Exercise 1: Execute the following for SSE: 
1a. Create a dataset: Generate a text corpus of at least ten documents. Each document 
should contain multiple words. 
1b. Implement encryption and decryption functions: Use the AES encryption and 
decryption functions. 
1c. Create an inverted index: Build an inverted index mapping word to the list of document 
IDs containing those words. 
 
- Encrypt the index using the provided encryption function. 
1d. Implement the search function: 
 
- Take a search query as input. 
 
- Encrypt the query. 
 
- Search the encrypted index for matching terms. 
 
- Decrypt the returned document IDs and display the corresponding documents 
 
Lab Exercise 2: Execute the following for PKSE: 
2a. Create a dataset: 
 
- Generate a text corpus of at least ten documents. Each document should contain 
multiple words. 
2b. Implement encryption and decryption functions: Use the Paillier cryptosystem for 
encryption and decryption. 


55 
2c. Create an encrypted index:  
 
- Build an inverted index mapping word to the list of document IDs containing those 
words. 
 
- Encrypt the index using the Paillier cryptosystem. 
2d. Implement the search function: 
o Take a search query as input. 
o Encrypt the query using the public key. 
o Search the encrypted index for matching terms. 
o Decrypt the returned document IDs using the private key. 
 
Additional Questions: 
1. Demonstrate how to securely store and transmit data using GnuPG. Additionally, show 
how to create a digital signature for the data and verify the signature after transmission. 
2. Configure and use Snort as a Network Intrusion Detection System (NIDS) to monitor 
realtime network traffic. Capture network traffic, apply Snort rules, and analyze the logs 
to identify any potential intrusions. 
 
 
 
 
 
 
 
 
 
 
 
 


56 
DBS LAB MANUAL 
INTRODUCTION TO VC# AND SQL PLUS EDITOR 
vi 
 
LAB NO.: 09 
Date: 
 
 
Project Design 
 
Objectives: 
• To design the UI and data aspectsof the mini project. 
 
Lab exercises: 
1. Design the SRS, UML and other aspects related to project 
 
 
 
[OBSERVATION SPACE –
```
