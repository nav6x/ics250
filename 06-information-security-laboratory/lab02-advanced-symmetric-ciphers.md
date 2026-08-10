# LAB 2: Advanced Symmetric Key Ciphers

[← Back to Course README](../README.md)

- [Official ICAS Cyber Security Laboratory Manual & Record](#official-icas-cyber-security-laboratory-manual-record)

> **Topic**: LAB 2: Advanced Symmetric Key Ciphers: Official ICAS Cyber Security Laboratory Manual & Record, ---------- Imports ----------, ---------- Main Execution ----------, DES requires exactly 8-byte key

---

## Official ICAS Cyber Security Laboratory Manual & Record

```markdown
Lab Exercises
1.
Encrypt the message "Confidential Data" using DES with the following key: "A1B2C3D4". 
Then decrypt the ciphertext to verify the original message.


# ---------- Imports ----------
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
# ---------- Main Execution ----------
message = "Confidential Data"
# DES requires exactly 8-byte key
key = b"A1B2C3D4"
# ---------- Encryption ----------
# ECB mode: simplest block cipher mode (not secure in practice)
cipher_encrypt = DES.new(key, DES.MODE_ECB)
# DES works on 8-byte blocks → padding is required
padded_message = pad(message.encode(), DES.block_size)
ciphertext = cipher_encrypt.encrypt(padded_message)
# ---------- Decryption ----------
cipher_decrypt = DES.new(key, DES.MODE_ECB)
decrypted_padded = cipher_decrypt.decrypt(ciphertext)
decrypted_message = unpad(decrypted_padded, DES.block_size).decode()
# ---------- Output ----------
print("Original Message:", message)
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted Message:", decrypted_message)
Original Message: Confidential Data
Ciphertext (hex): 20089c56693b4b0a685304930baf3ed459a54a2e4ada7187
Decrypted Message: Confidential Data
1.
Encrypt the message "Sensitive Information" using AES-128 with the following key: 
"0123456789ABCDEF0123456789ABCDEF". Then decrypt the ciphertext to verify the 
original message.
# ---------- Imports ----------
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# ---------- Main Execution ----------
message = "Sensitive Information"


# Convert hex string to bytes (required for AES)
key_hex = "0123456789ABCDEF0123456789ABCDEF"
key = bytes.fromhex(key_hex)
# ---------- Encryption ----------
cipher_encrypt = AES.new(key, AES.MODE_ECB)
# AES uses 16-byte blocks
padded_message = pad(message.encode(), AES.block_size)
ciphertext = cipher_encrypt.encrypt(padded_message)
# ---------- Decryption ----------
cipher_decrypt = AES.new(key, AES.MODE_ECB)
decrypted_padded = cipher_decrypt.decrypt(ciphertext)
decrypted_message = unpad(decrypted_padded, AES.block_size).decode()
# ---------- Output ----------
print("Original Message:", message)
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted Message:", decrypted_message)
Original Message: Sensitive Information
Ciphertext (hex): 
99be7e3714ab880d4927596b5658130b055b7a63692d0df800228eed299a422c
Decrypted Message: Sensitive Information
1.
Compare the encryption and decryption times for DES and AES-256 for the message 
"Performance Testing of Encryption Algorithms". Use a standard implementation and 
report your findings.
# ---------- Imports ----------
import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
# ---------- Main Execution ----------
message = "Performance Testing of Encryption Algorithms"
# Number of repetitions to get measurable time
iterations = 100000
# DES key (8 bytes)
des_key = b"8bytekey"


# AES-256 key (32 bytes)
aes_key = b"thisisa32bytekeyforaes256testing"
# Padding (block sizes differ)
padded_des = pad(message.encode(), DES.block_size)
padded_aes = pad(message.encode(), AES.block_size)
# ---------- DES Timing ----------
des_cipher = DES.new(des_key, DES.MODE_ECB)
start_time = time.perf_counter()
for _ in range(iterations):
    des_cipher.encrypt(padded_des)
des_time = time.perf_counter() - start_time
# ---------- AES-256 Timing ----------
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
start_time = time.perf_counter()
for _ in range(iterations):
    aes_cipher.encrypt(padded_aes)
aes_time = time.perf_counter() - start_time
# ---------- Output ----------
print("Message:", message)
print()
print(f"DES Time ({iterations} runs): {des_time:.4f} seconds")
print(f"AES-256 Time ({iterations} runs): {aes_time:.4f} seconds")
# ---------- Simple Comparison ----------
if aes_time < des_time:
    print("\nAES-256 is faster than DES")
else:
    print("\nDES is faster than AES-256")
Message: Performance Testing of Encryption Algorithms
DES Time (100000 runs): 5.5302 seconds
AES-256 Time (100000 runs): 3.2652 seconds
AES-256 is faster than DES


1.
Encrypt the message "Classified Text" using Triple DES with the key 
"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF". Then decrypt the 
ciphertext to verify the original message.
# ---------- Imports ----------
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
# ---------- Main Execution ----------
message = "Classified Text"
# 24-byte key (48 hex chars = 24 bytes)
key_hex = "1234567890ABCDEFFEDCBA09876543211234567890ABCDEF"
key = bytes.fromhex(key_hex)
# ---------- Encryption ----------
cipher_encrypt = DES3.new(key, DES3.MODE_ECB)
padded_message = pad(message.encode(), DES3.block_size)
ciphertext = cipher_encrypt.encrypt(padded_message)
# ---------- Decryption ----------
cipher_decrypt = DES3.new(key, DES3.MODE_ECB)
decrypted_padded = cipher_decrypt.decrypt(ciphertext)
decrypted_message = unpad(decrypted_padded, DES3.block_size).decode()
# ---------- Output ----------
print("Original Message:", message)
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted Message:", decrypted_message)
Original Message: Classified Text
Ciphertext (hex): c28e11ea40da61ac93bb958cf609a64d
Decrypted Message: Classified Text
1.
Encrypt the message "Top Secret Data" using AES-192 with the key 
"FEDCBA9876543210FEDCBA9876543210". Show all the steps involved in the 
encryption process (key expansion, initial round, main rounds, final round).
# ---------- Imports ----------
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
# ---------- Main Execution ----------


message = "Top Secret Data"
# Extend key to 24 bytes (AES-192 requirement)
key_hex = "FEDCBA9876543210FEDCBA9876543210" + "0000000000000000"
key = bytes.fromhex(key_hex)
# ---------- Encryption ----------
cipher = AES.new(key, AES.MODE_ECB)
padded_message = pad(message.encode(), AES.block_size)
ciphertext = cipher.encrypt(padded_message)
# ---------- Output ----------
print("Original Message:", message)
print("Ciphertext (hex):", ciphertext.hex())
print()
# ---------- AES-192 Steps Explanation ----------
print("AES-192 Encryption Steps:\n")
print("1. Key Expansion:")
print("   - 192-bit key is expanded into 13 round keys")
print("   - Each round uses a different subkey")
print("\n2. Initial Round:")
print("   - AddRoundKey: plaintext XOR first round key")
print("\n3. Main Rounds (1 to 11):")
print("   - SubBytes: Substitute bytes using S-box (non-linear)")
print("   - ShiftRows: Shift rows to create diffusion")
print("   - MixColumns: Mix columns mathematically")
print("   - AddRoundKey: XOR with round key")
print("\n4. Final Round (12):")
print("   - SubBytes")
print("   - ShiftRows")
print("   - AddRoundKey")
print("   - (No MixColumns here)")
Original Message: Top Secret Data
Ciphertext (hex): 091e28b2d1ce9bb8c49c227658541e8e
AES-192 Encryption Steps:
1. Key Expansion:
   - 192-bit key is expanded into 13 round keys
   - Each round uses a different subkey
2. Initial Round:


   - AddRoundKey: plaintext XOR first round key
3. Main Rounds (1 to 11):
   - SubBytes: Substitute bytes using S-box (non-linear)
   - ShiftRows: Shift rows to create diffusion
   - MixColumns: Mix columns mathematically
   - AddRoundKey: XOR with round key
4. Final Round (12):
   - SubBytes
   - ShiftRows
   - AddRoundKey
   - (No MixColumns here)
Additional Exercises
1.
Using DES and AES (128, 192, and 256 bits key) encrypt the five different messages using 
same key.
–
a. Consider different modes of operation
–
b. Plot the graph which shows execution time taken by each technique.
–
c. Compare time taken by different modes of operation
# ---------- Imports ----------
import time
import matplotlib.pyplot as plt
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
# ---------- Messages ----------
messages = [
    "First message for encryption test.",
    "Second message with some different content.",
    "Third message, short one.",
    "Fourth message, making it a bit longer to test block ciphers.",
    "Fifth message to complete the test."
]
# ---------- Keys ----------
base_key = b"ThisIsABaseKeyThatIs32BytesLong!"
keys = {
    "DES": base_key[:8],
    "AES-128": base_key[:16],
    "AES-192": base_key[:24],
    "AES-256": base_key[:32]
}
# ---------- Modes ----------
modes = {


    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC,
    "CFB": AES.MODE_CFB
}
# IVs (required for CBC/CFB)
iv_des = base_key[:8]
iv_aes = base_key[:16]
# ---------- Timing Setup ----------
iterations = 3000
results = {algo: {} for algo in keys}
# ---------- Performance Measurement ----------
for algo, key in keys.items():
    for mode_name, mode in modes.items():
        
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            for msg in messages:
                
                block_size = 8 if algo == "DES" else 16
                padded_msg = pad(msg.encode(), block_size)
                
                # Select cipher
                if algo == "DES":
                    if mode_name in ["CBC", "CFB"]:
                        cipher = DES.new(key, mode, iv_des)
                    else:
                        cipher = DES.new(key, mode)
                else:
                    if mode_name in ["CBC", "CFB"]:
                        cipher = AES.new(key, mode, iv_aes)
                    else:
                        cipher = AES.new(key, mode)
                
                cipher.encrypt(padded_msg)
        
        end_time = time.perf_counter()
        results[algo][mode_name] = (end_time - start_time) * 1000  # 
ms
# ---------- Print Results ----------
print("Execution Time (milliseconds):\n")
for algo in results:
    print(algo)


    for mode in results[algo]:
        print(f"  {mode}: {results[algo][mode]:.2f} ms")
    print()
# ---------- Plot Graph ----------
for mode in modes:
    algos = list(results.keys())
    times = [results[a][mode] for a in algos]
    
    plt.figure()
    plt.title(f"Performance Comparison ({mode} Mode)")
    plt.xlabel("Algorithms")
    plt.ylabel("Time (ms)")
    plt.bar(algos, times)
    plt.show()
Execution Time (milliseconds):
DES
  ECB: 3050.16 ms
  CBC: 4461.89 ms
  CFB: 5074.58 ms
AES-128
  ECB: 2498.37 ms
  CBC: 3248.78 ms
  CFB: 3434.03 ms
AES-192
  ECB: 1988.74 ms
  CBC: 3677.89 ms
  CFB: 4833.72 ms
AES-256
  ECB: 1793.48 ms
  CBC: 3679.93 ms
  CFB: 4157.94 ms






1.
Encrypt the following block of data using DES with the key "A1B2C3D4E5F60708". 
The data to be encrypted is: Mathematica
 
Block1: 
54686973206973206120636f6e666964656e7469616c206d657373616765
 
Block2: 416e64207468697320697320746865207365636f6e6420626c6f636b
–
a. Provide the ciphertext for each block.
–
b. Decrypt the ciphertext to retrieve the original plaintext blocks.
# ---------- Imports ----------
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
# ---------- Main Execution ----------
# Convert key from hex to bytes
key = bytes.fromhex("A1B2C3D4E5F60708")
# Hex blocks
block1_hex = 
"54686973206973206120636f6e666964656e7469616c206d657373616765"


block2_hex = 
"416e64207468697320697320746865207365636f6e6420626c6f636b"
# Convert to bytes
block1 = bytes.fromhex(block1_hex)
block2 = bytes.fromhex(block2_hex)
# ---------- Encryption ----------
cipher = DES.new(key, DES.MODE_ECB)
ciphertext1 = cipher.encrypt(pad(block1, DES.block_size))
ciphertext2 = cipher.encrypt(pad(block2, DES.block_size))
# ---------- Decryption ----------
decrypted1 = unpad(cipher.decrypt(ciphertext1), DES.block_size)
decrypted2 = unpad(cipher.decrypt(ciphertext2), DES.block_size)
# ---------- Output ----------
print("Block 1 Ciphertext:", ciphertext1.hex())
print("Block 2 Ciphertext:", ciphertext2.hex())
print("\nDecrypted Block 1:", decrypted1.decode())
print("Decrypted Block 2:", decrypted2.decode())
Block 1 Ciphertext: 
ca4174021e85fa3584ba263409f0e10bff0f049c24c44793185c80d14d7e490e
Block 2 Ciphertext: 
910563c86f7c68b6e2c16b7d18451a7c22e01379abcb8403ae6c9c9d19b3b798
Decrypted Block 1: This is a confidential message
Decrypted Block 2: And this is the second block
1.
Using AES-256, encrypt the message "Encryption Strength" with the key 
"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF". 
Then decrypt the ciphertext to verify the original message.
# ---------- Imports ----------
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# ---------- Main Execution ----------
message = "Encryption Strength"
# Convert 64-hex-character key → 32 bytes
key_hex = 
"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"


key = bytes.fromhex(key_hex)
# ---------- Encryption ----------
cipher_encrypt = AES.new(key, AES.MODE_ECB)
# AES block size = 16 bytes → padding needed
padded_message = pad(message.encode(), AES.block_size)
ciphertext = cipher_encrypt.encrypt(padded_message)
# ---------- Decryption ----------
cipher_decrypt = AES.new(key, AES.MODE_ECB)
decrypted_padded = cipher_decrypt.decrypt(ciphertext)
decrypted_message = unpad(decrypted_padded, AES.block_size).decode()
# ---------- Output ----------
print("Original Message:", message)
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted Message:", decrypted_message)
Original Message: Encryption Strength
Ciphertext (hex): 
950bd5b8b9f399b41764f0237d81104bc4695ba3606748b0eba5b0c42b256db8
Decrypted Message: Encryption Strength
1.
Encrypt the message "Secure Communication" using DES in Cipher Block Chaining (CBC) 
mode with the key "A1B2C3D4" and an initialization vector (IV) of "12345678". Provide 
the ciphertext and then decrypt it to retrieve the original message.
# ---------- Imports ----------
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
# ---------- Main Execution ----------
message = "Secure Communication"
# DES key (8 bytes)
key = b"A1B2C3D4"
# Initialization Vector (must be 8 bytes for DES)
iv = b"12345678"
# ---------- Encryption ----------
cipher_encrypt = DES.new(key, DES.MODE_CBC, iv)


padded_message = pad(message.encode(), DES.block_size)
ciphertext = cipher_encrypt.encrypt(padded_message)
# ---------- Decryption ----------
cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)
decrypted_padded = cipher_decrypt.decrypt(ciphertext)
decrypted_message = unpad(decrypted_padded, DES.block_size).decode()
# ---------- Output ----------
print("Original Message:", message)
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted Message:", decrypted_message)
Original Message: Secure Communication
Ciphertext (hex): 248a096ffffb6459dc76a423b1b22f15f642b95a4bc1c307
Decrypted Message: Secure Communication
1.
Encrypt the message "Cryptography Lab Exercise" using AES in Counter (CTR) mode with 
the key "0123456789ABCDEF0123456789ABCDEF" and a nonce of 
"0000000000000000". Provide the ciphertext and then decrypt it to retrieve the 
original message.
# ---------- Imports ----------
from Crypto.Cipher import AES
from Crypto.Util import Counter
# ---------- Main Execution ----------
message = "Cryptography Lab Exercise"
# Convert hex key → bytes (16 bytes → AES-128)
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
# Nonce (used to initialize counter)
nonce = bytes.fromhex("0000000000000000")
# ---------- Encryption ----------
# Counter = nonce || incrementing value
counter_enc = Counter.new(64, prefix=nonce)
cipher_encrypt = AES.new(key, AES.MODE_CTR, counter=counter_enc)
ciphertext = cipher_encrypt.encrypt(message.encode())


# ---------- Decryption ----------
# IMPORTANT: same nonce + counter setup must be reused
counter_dec = Counter.new(64, prefix=nonce)
cipher_decrypt = AES.new(key, AES.MODE_CTR, counter=counter_dec)
decrypted_message = cipher_decrypt.decrypt(ciphertext).decode()
# ---------- Output ----------
print("Original Message:", message)
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted Message:", decrypted_message)
Original Message: Cryptography Lab Exercise
Ciphertext (hex): 809fbe9d84fc95a02a6a009b353b3c507e60b453c954d3d436
Decrypted Message: Cryptography Lab Exercise
```
