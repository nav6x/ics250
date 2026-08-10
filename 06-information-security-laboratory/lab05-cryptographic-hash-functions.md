# LAB 5: Hashing

[← Back to Course README](../README.md)

- [Official ICAS Cyber Security Laboratory Manual & Record](#official-icas-cyber-security-laboratory-manual-record)

> **Topic**: LAB 5: Hashing: Official ICAS Cyber Security Laboratory Manual & Record, ---------- Custom Hash Function ----------, Efficient multiplication: hash * 33 = (hash << 5) + hash, Keep within 32-bit range (important for consistency)

---

## Official ICAS Cyber Security Laboratory Manual & Record



```markdown

Lab Exercises

1.

Implement the hash function in Python. Your function should start with an initial hash 

value of 5381 and for each character in the input string, multiply the current hash value 

by 33, add the ASCII value of the character, and use bitwise operations to ensure 

thorough mixing of the bits. Finally, ensure the hash value is kept within a 32-bit range by 

applying an appropriate mask.

# ---------- Custom Hash Function ----------

def custom_hash(input_string):

    """

    DJB2-style hash:

    hash = hash * 33 + char

    Uses bit masking to keep value within 32 bits.

    """





    hash_val = 5381  # Standard initial value

    for char in input_string:

        # Efficient multiplication: hash * 33 = (hash << 5) + hash

        hash_val = ((hash_val << 5) + hash_val) + ord(char)

        # Keep within 32-bit range (important for consistency)

        hash_val = hash_val & 0xFFFFFFFF

    return hash_val

# ---------- Testing ----------

print("--- Custom 32-bit Hash Function ---\n")

test_strings = [

    "Information Security",

    "information security",

    "Hashing",

    "HashinG"

]

for text in test_strings:

    print(f"Text: '{text}'")

    print(f"Hash: {hex(custom_hash(text))}\n")

--- Custom 32-bit Hash Function ---

Text: 'Information Security'

Hash: 0xde399063

Text: 'information security'

Hash: 0xeb59f8a3

Text: 'Hashing'

Hash: 0x94c0ef47

Text: 'HashinG'

Hash: 0x94c0ef27

1.

Using socket programming in Python, demonstrate the application of hash functions for 

ensuring data integrity during transmission over a network. Write server and client 

scripts where the server computes the hash of received data and sends it back to the 

client, which then verifies the integrity of the data by comparing the received hash with 

the locally computed hash. Show how the hash verification detects data corruption or 

tampering during transmission.

# ---------- Imports ----------

import socket

import threading





import hashlib

import time

# ---------- Configuration ----------

HOST = '127.0.0.1'

PORT = 65432

# ---------- Server ----------

def server_thread():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        s.bind((HOST, PORT))

        s.listen()

        conn, addr = s.accept()

        with conn:

            # Scenario 1: Normal transmission

            data1 = conn.recv(1024)

            hash1 = hashlib.sha256(data1).hexdigest()

            conn.sendall(hash1.encode())

            # Scenario 2: Tampered transmission

            data2 = conn.recv(1024)

            # Simulating attacker modifying data

            tampered_data = data2.replace(b"Secret", b"S3cret")

            hash2 = hashlib.sha256(tampered_data).hexdigest()

            conn.sendall(hash2.encode())

# ---------- Client ----------

def client_thread():

    time.sleep(0.5)  # Allow server to start

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.connect((HOST, PORT))

        message = b"Top Secret Data"

        expected_hash = hashlib.sha256(message).hexdigest()

        print(f"[Client] Original Message: {message.decode()}")

        print(f"[Client] Expected Hash: {expected_hash}\n")

        # ---------- Scenario 1 ----------

        s.sendall(message)

        received_hash1 = s.recv(1024).decode()

        print("[Scenario 1: Clean Transmission]")





        print(f"Received Hash: {received_hash1}")

        if expected_hash == received_hash1:

            print("→ INTEGRITY VERIFIED: Data is intact.\n")

        else:

            print("→ INTEGRITY FAILED: Data altered.\n")

        # ---------- Scenario 2 ----------

        s.sendall(message)

        received_hash2 = s.recv(1024).decode()

        print("[Scenario 2: Tampered Transmission (MITM Attack)]")

        print(f"Received Hash: {received_hash2}")

        if expected_hash == received_hash2:

            print("→ INTEGRITY VERIFIED: Data is intact.\n")

        else:

            print("→ ALERT! Data tampered (hash mismatch detected!)\

n")

# ---------- Run ----------

print("--- Network Integrity Verification ---\n")

server = threading.Thread(target=server_thread)

server.start()

client_thread()

server.join()

--- Network Integrity Verification ---

[Client] Original Message: Top Secret Data

[Client] Expected Hash: 

65f699de55444ad65c3fbeea4c718a316bbf890e8c101c3424122d0e1fe85aef

[Scenario 1: Clean Transmission]

Received Hash: 

65f699de55444ad65c3fbeea4c718a316bbf890e8c101c3424122d0e1fe85aef

→ INTEGRITY VERIFIED: Data is intact.

[Scenario 2: Tampered Transmission (MITM Attack)]

Received Hash: 

9010b81e51aa1dcde0beca4a6d0fba84f7d2f9c0bed65fe30fd357a15cde3ab2

→ ALERT! Data tampered (hash mismatch detected!)

1.

Design a Python-based experiment to analyze the performance of MD5, SHA-1, and SHA-

256 hashing techniques in terms of computation time and collision resistance. Generate 

a dataset of random strings ranging from 50 to 100 strings, compute the hash values 





using each hashing technique, and measure the time taken for hash computation. 

Implement collision detection algorithms to identify any collisions within the hashed 

dataset.

# ---------- Imports ----------

import hashlib

import time

import random

import string

# ---------- Dataset Generator ----------

def generate_dataset(num_strings=100):

    """

    Generates random strings to simulate real-world data.

    Larger dataset → better collision testing.

    """

    dataset = []

    for _ in range(num_strings):

        length = random.randint(50, 100)

        rand_str = ''.join(random.choices(string.ascii_letters + 

string.digits, k=length))

        dataset.append(rand_str.encode('utf-8'))

    return dataset

# ---------- Benchmark Function ----------

def benchmark_hashes(dataset):

    algorithms = {

        'MD5': hashlib.md5,

        'SHA-1': hashlib.sha1,

        'SHA-256': hashlib.sha256

    }

    print(f"{'Algorithm':<10} | {'Time ms':<15} | {'Collisions'}")

    print("-" * 50)

    for name, func in algorithms.items():

        hash_set = set()

        collisions = 0

        start_time = time.perf_counter()

        for data in dataset:

            h = func(data).hexdigest()

            # Collision detection

            if h in hash_set:

                collisions += 1





            else:

                hash_set.add(h)

        end_time = time.perf_counter()

        total_time_ms = (end_time - start_time) * 1000

        print(f"{name:<10} | {total_time_ms:<15.4f} | {collisions}")

# ---------- Execution ----------

print("--- Hash Performance & Collision Analysis ---\n")

data = generate_dataset(100)

print(f"Dataset size: {len(data)} random inputs\n")

benchmark_hashes(data)

--- Hash Performance & Collision Analysis ---

Dataset size: 100 random inputs

Algorithm  | Time ms       | Collisions

--------------------------------------------------

MD5        | 2.3280          | 0

SHA-1      | 3.4913          | 0

SHA-256    | 1.7895          | 0

Additional Exercise

1.

Write server and client scripts where the client sends a message in multiple parts to the 

server, the server reassembles the message, computes the hash of the reassembled 

message, and sends this hash back to the client. The client then verifies the integrity of 

the message by comparing the received hash with the locally computed hash of the 

original message.

# ---------- Imports ----------

import socket

import threading

import hashlib

import time

# ---------- Configuration ----------

HOST = '127.0.0.1'

PORT = 65433

# ---------- Server ----------

def multipart_server():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:





        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        s.bind((HOST, PORT))

        s.listen()

        conn, addr = s.accept()

        with conn:

            reassembled_data = b""

            while True:

                chunk = conn.recv(1024)

                if not chunk:

                    break

                # Detect end of transmission

                if b"<EOF>" in chunk:

                    reassembled_data += chunk.replace(b"<EOF>", b"")

                    break

                reassembled_data += chunk

            print(f"[Server] Reassembled Message:\

n{reassembled_data.decode()}")

            # Compute hash of full reconstructed message

            final_hash = hashlib.sha256(reassembled_data).hexdigest()

            print(f"[Server] Sending Hash: {final_hash}")

            conn.sendall(final_hash.encode())

# ---------- Client ----------

def multipart_client():

    time.sleep(0.5)  # Ensure server starts first

    # Message split into chunks

    chunks = [

        b"This is part 1 of the message. ",

        b"Here is part 2, bridging the gap. ",

        b"And finally, part 3 concludes it."

    ]

    full_message = b"".join(chunks)

    # Compute expected hash BEFORE sending

    expected_hash = hashlib.sha256(full_message).hexdigest()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.connect((HOST, PORT))





        for i, chunk in enumerate(chunks):

            print(f"[Client] Sending Chunk {i+1}")

            s.sendall(chunk)

            time.sleep(0.1)

        # End-of-file marker

        s.sendall(b"<EOF>")

        # Receive hash from server

        server_hash = s.recv(1024).decode()

        print("\n--- Integrity Verification ---")

        print(f"Client Hash : {expected_hash}")

        print(f"Server Hash : {server_hash}")

        if expected_hash == server_hash:

            print("✔ SUCCESS: Message integrity preserved")

        else:

            print("❌ FAILURE: Message corrupted during transmission")

# ---------- Run ----------

print("--- Multipart Reassembly & Integrity Check ---\n")

server = threading.Thread(target=multipart_server)

server.start()

multipart_client()

server.join()

--- Multipart Reassembly & Integrity Check ---

[Client] Sending Chunk 1

[Client] Sending Chunk 2

[Client] Sending Chunk 3

[Server] Reassembled Message:

This is part 1 of the message. Here is part 2, bridging the gap. And 

finally, part 3 concludes it.

[Server] Sending Hash: 

c8d28956b5214b12f411a144aac6e04fd48fcb70386b46af5f9682316e5d8e33

--- Integrity Verification ---

Client Hash : 

c8d28956b5214b12f411a144aac6e04fd48fcb70386b46af5f9682316e5d8e33

Server Hash : 

c8d28956b5214b12f411a144aac6e04fd48fcb70386b46af5f9682316e5d8e33

✔ SUCCESS: Message integrity preserved

```
