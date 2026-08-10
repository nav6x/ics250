# LAB 6: Digital Signature

[← Back to Course README](../README.md)

- [Official ICAS Cyber Security Laboratory Manual & Record](#official-icas-cyber-security-laboratory-manual-record)
> **Topic**: LAB 6: Digital Signature: Official ICAS Cyber Security Laboratory Manual & Record, ---------- Imports ----------, ---------- ElGamal Signature ----------, Hash the message (sign the hash, not raw message)

---

## Official ICAS Cyber Security Laboratory Manual & Record

```markdown
Lab Exercises
1.
Try using the Elgammal, Schnor asymmetric encryption standard and verify the above 
steps.
# ---------- Imports ----------
import hashlib
import random
import math
import sympy
from Crypto.Util.number import getPrime, inverse, bytes_to_long
# ---------- ElGamal Signature ----------
def elgamal_signature_demo():
    print("\n--- ElGamal Digital Signature ---")
    message = b"Important Contract Document"
    # Hash the message (sign the hash, not raw message)
    m_hash = bytes_to_long(hashlib.sha256(message).digest())
    # Key Generation
    p = getPrime(256)
    g = 2
    x = random.randint(2, p - 2)   # private key
    y = pow(g, x, p)               # public key
    # Choose k such that gcd(k, p-1) = 1
    while True:
        k = random.randint(2, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    # Signature generation
    r = pow(g, k, p)
    k_inv = inverse(k, p - 1)
    s = ((m_hash - x * r) * k_inv) % (p - 1)
    print(f"Message: {message.decode()}")
    print(f"Signature (r, s): r={r}, s={s}")
    # Verification
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m_hash, p)
    print("Verification:", "SUCCESS" if v1 == v2 else "FAILED")


# ---------- Schnorr Signature ----------
def schnorr_signature_demo():
    print("\n--- Schnorr Digital Signature ---")
    message = b"Authorize Payment of $500"
    # Generate safe prime p = 2q + 1
    q = getPrime(160)
    p = 2 * q + 1
    while not sympy.isprime(p):
        q = getPrime(160)
        p = 2 * q + 1
    # Generator
    h = random.randint(2, p - 2)
    g = pow(h, 2, p)
    # Keys
    x = random.randint(1, q - 1)   # private
    y = pow(g, x, p)               # public
    # Signature
    k = random.randint(1, q - 1)
    r = pow(g, k, p)
    e = bytes_to_long(hashlib.sha256(message + 
str(r).encode()).digest()) % q
    s = (k - x * e) % q
    print(f"Message: {message.decode()}")
    print(f"Signature (e, s): e={e}, s={s}")
    # Verification
    r_v = (pow(g, s, p) * pow(y, e, p)) % p
    e_v = bytes_to_long(hashlib.sha256(message + 
str(r_v).encode()).digest()) % q
    print("Verification:", "SUCCESS" if e_v == e else "FAILED")
# ---------- Run ----------
print("--- Digital Signatures ---")
elgamal_signature_demo()
schnorr_signature_demo()
--- Digital Signatures ---
--- ElGamal Digital Signature ---
Message: Important Contract Document
Signature (r, s): 


r=54387658424020349646038696483664251756102281839799861280447723120101
44856489, 
s=21079554009505332848930479609917441956470537426242291707100861459609
112116111
Verification: SUCCESS
--- Schnorr Digital Signature ---
Message: Authorize Payment of $500
Signature (e, s): e=692976382629679048766948527600518999151040062007, 
s=324143805402333350707209238645771996296653206205
Verification: SUCCESS
1.
Try using the Diffie-Hellman asymmetric encryption standard and verify the above steps.
# ---------- Imports ----------
import hashlib
import random
import math
import sympy
from Crypto.Util.number import getPrime, inverse, bytes_to_long
# ---------- ElGamal Signature ----------
def elgamal_signature_demo():
    print("\n--- ElGamal Digital Signature ---")
    message = b"Important Contract Document"
    # Hash the message (sign the hash, not raw message)
    m_hash = bytes_to_long(hashlib.sha256(message).digest())
    # Key Generation
    p = getPrime(256)
    g = 2
    x = random.randint(2, p - 2)   # private key
    y = pow(g, x, p)               # public key
    # Choose k such that gcd(k, p-1) = 1
    while True:
        k = random.randint(2, p - 2)
        if math.gcd(k, p - 1) == 1:
            break
    # Signature generation
    r = pow(g, k, p)
    k_inv = inverse(k, p - 1)
    s = ((m_hash - x * r) * k_inv) % (p - 1)
    print(f"Message: {message.decode()}")
    print(f"Signature (r, s): r={r}, s={s}")


    # Verification
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, m_hash, p)
    print("Verification:", "SUCCESS" if v1 == v2 else "FAILED")
# ---------- Schnorr Signature ----------
def schnorr_signature_demo():
    print("\n--- Schnorr Digital Signature ---")
    message = b"Authorize Payment of $500"
    # Generate safe prime p = 2q + 1
    q = getPrime(160)
    p = 2 * q + 1
    while not sympy.isprime(p):
        q = getPrime(160)
        p = 2 * q + 1
    # Generator
    h = random.randint(2, p - 2)
    g = pow(h, 2, p)
    # Keys
    x = random.randint(1, q - 1)   # private
    y = pow(g, x, p)               # public
    # Signature
    k = random.randint(1, q - 1)
    r = pow(g, k, p)
    e = bytes_to_long(hashlib.sha256(message + 
str(r).encode()).digest()) % q
    s = (k - x * e) % q
    print(f"Message: {message.decode()}")
    print(f"Signature (e, s): e={e}, s={s}")
    # Verification
    r_v = (pow(g, s, p) * pow(y, e, p)) % p
    e_v = bytes_to_long(hashlib.sha256(message + 
str(r_v).encode()).digest()) % q
    print("Verification:", "SUCCESS" if e_v == e else "FAILED")
# ---------- Run ----------
print("--- Digital Signatures ---")


elgamal_signature_demo()
schnorr_signature_demo()
--- Digital Signatures ---
--- ElGamal Digital Signature ---
Message: Important Contract Document
Signature (r, s): 
r=49645366710293744082160994300641269613391460585522085381254117068028
533951088, 
s=50289247633216376155717471096308565727730173330435659258654284012859
688996103
Verification: SUCCESS
--- Schnorr Digital Signature ---
Message: Authorize Payment of $500
Signature (e, s): e=826971126772246706530974934872987620284986023463, 
s=14017952113707559889642310535210968984254548220
Verification: SUCCESS
1.
Try the same in a client server-based scenario and record your observation and analysis.
# ---------- Imports ----------
import socket
import threading
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
# ---------- Configuration ----------
HOST = '127.0.0.1'
PORT = 65435
# ---------- Server ----------
def signature_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            raw_data = conn.recv(4096).split(b"|||")
            pub_key_bytes = raw_data[0]
            signature = raw_data[1]
            message = raw_data[2]


            print(f"[Server] Received Message: {message.decode()}")
            public_key = RSA.import_key(pub_key_bytes)
            # Hash message before verification
            h = SHA256.new(message)
            try:
                pkcs1_15.new(public_key).verify(h, signature)
                print("✔ Signature VERIFIED → Message is authentic")
            except (ValueError, TypeError):
                print("❌ Signature INVALID → Message rejected")
# ---------- Client ----------
def signature_client():
    time.sleep(0.5)
    # Generate RSA keys
    key = RSA.generate(1024)
    private_key = key
    public_key = key.publickey().export_key()
    message = b"Transfer $10,000 to Account B."
    # Hash + Sign
    h = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(h)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[Client] Sending signed message...")
        payload = public_key + b"|||" + signature + b"|||" + message
        s.sendall(payload)
# ---------- Run ----------
print("--- Client-Server Signature Verification ---\n")
server = threading.Thread(target=signature_server)
server.start()
signature_client()
server.join()
--- Client-Server Signature Verification ---
[Client] Sending signed message...


[Server] Received Message: Transfer $10,000 to Account B.
✔ Signature VERIFIED → Message is authentic
Additional Exercise
1.
Explore the link https://www.nmichaels.org/rsa.py for better understanding. 
Demonstrate CIA traid using RSA encryption and digital signature along with SHA 
hashing.
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
def demonstrate_cia_triad():
    print("\n--- CIA Triad Demonstration ---\n")
    # -------------------------------
    # Step 1: Key Generation
    # -------------------------------
    alice_key = RSA.generate(2048)   # Sender
    bob_key = RSA.generate(2048)     # Receiver
    alice_private = alice_key
    alice_public = alice_key.publickey()
    bob_private = bob_key
    bob_public = bob_key.publickey()
    # -------------------------------
    # Original Message
    # -------------------------------
    message = b"Top Secret Financial Merger Data"
    print(f"Original Message: {message.decode()}\n")
    # -------------------------------
    # 1. INTEGRITY (Hashing)
    # -------------------------------
    hash_msg = SHA256.new(message)
    print("✔ Integrity: Message hashed using SHA-256")
    # -------------------------------
    # 2. AUTHENTICATION (Signature)
    # -------------------------------
    signature = pkcs1_15.new(alice_private).sign(hash_msg)
    print("✔ Authentication: Message signed with Alice's private key")
    # -------------------------------
    # 3. CONFIDENTIALITY (Encryption)
    # -------------------------------


    cipher = PKCS1_OAEP.new(bob_public)
    encrypted_message = cipher.encrypt(message)
    print("✔ Confidentiality: Message encrypted using Bob's public 
key\n")
    print(">>> Data Sent Over Network <<<\n")
    # -------------------------------
    # Receiver Side (Bob)
    # -------------------------------
    # Decrypt Message
    decrypt_cipher = PKCS1_OAEP.new(bob_private)
    decrypted_message = decrypt_cipher.decrypt(encrypted_message)
    print(f"[Bob] Decrypted Message: {decrypted_message.decode()}")
    # Verify Signature
    received_hash = SHA256.new(decrypted_message)
    try:
        pkcs1_15.new(alice_public).verify(received_hash, signature)
        print("[Bob] ✔ Signature Verified (Authentication SUCCESS)")
    except:
        print("[Bob] ❌ Signature Verification FAILED")
# Run
demonstrate_cia_triad()
--- CIA Triad Demonstration ---
Original Message: Top Secret Financial Merger Data
✔ Integrity: Message hashed using SHA-256
✔ Authentication: Message signed with Alice's private key
✔ Confidentiality: Message encrypted using Bob's public key
>>> Data Sent Over Network <<<
[Bob] Decrypted Message: Top Secret Financial Merger Data
[Bob] ✔ Signature Verified (Authentication SUCCESS)
```
