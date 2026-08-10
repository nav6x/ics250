# LAB 4: Advanced Asymmetric Key Ciphers

[← Back to Course README](../README.md)

- [Official ICAS Cyber Security Laboratory Manual & Record](#official-icas-cyber-security-laboratory-manual-record)
> **Topic**: LAB 4: Advanced Asymmetric Key Ciphers: Official ICAS Cyber Security Laboratory Manual & Record, ---------- Imports ----------, ---------- Logging Setup ----------, ---------- Key Management System ----------

---

## Official ICAS Cyber Security Laboratory Manual & Record

```markdown
Lab Exercises
Question 1
SecureCorp is a large enterprise with multiple subsidiaries and business units located across 
different geographical regions. As part of their digital transformation initiative, the IT team at 
SecureCorp has been tasked with building a secure and scalable communication system to 
enable seamless collaboration and information sharing between their various subsystems.
The enterprise system consists of the following key subsystems:
1.
Finance System (System A): Responsible for all financial record-keeping, accounting, and 
reporting.
2.
HR System (System B): Manages employee data, payroll, and personnel related 
processes.


3.
Supply Chain Management (System C): Coordinates the flow of goods, services, and 
information across the organization's supply chain
These subsystems need to communicate securely and exchange critical documents, such 
financial reports, employee contracts, and procurement orders, to ensure the enterprise's 
overall efficiency.
The IT team at SecureCorp has identified the following requirements for the secure 
communication and document signing solution:
1.
Secure Communication: The subsystems must be able to establish secure 
communication channels using a combination of RSA encryption and Diffie-Hellman key 
exchange.
2.
Key Management: SecureCorp requires a robust key management system to generate, 
distribute, and revoke keys as needed to maintain the security of the enterprise system.
3.
Scalability: The solution must be designed to accommodate the addition of new 
subsystems in the future as SecureCorp continues to grow and expand its operations.
Implement a Python program which incorporates the requirements.
# ---------- Imports ----------
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import hashes, serialization
# ---------- Logging Setup ----------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %
(levelname)s - %(message)s')
# ---------- Key Management System ----------
class KeyManagementSystem:
    def __init__(self):
        self.registry = {}
        # DH parameters must be common for both parties
        logging.info("KMS: Generating shared DH parameters...")
        self.dh_parameters = dh.generate_parameters(generator=2, 
key_size=2048)
        logging.info("KMS: Ready.\n")
    def register_subsystem(self, system_id):
        # Each subsystem gets RSA keys for identity verification
        private_key = rsa.generate_private_key(public_exponent=65537, 
key_size=2048)
        public_key = private_key.public_key()
        self.registry[system_id] = {
            'public_key': public_key,
            'status': 'ACTIVE'


        }
        logging.info(f"KMS: Registered {system_id}")
        return private_key, self.dh_parameters
    def get_public_key(self, system_id):
        if system_id in self.registry and self.registry[system_id]
['status'] == 'ACTIVE':
            return self.registry[system_id]['public_key']
        raise ValueError("System not found or revoked")
    def revoke_system(self, system_id):
        if system_id in self.registry:
            self.registry[system_id]['status'] = 'REVOKED'
            logging.warning(f"KMS: Revoked {system_id}")
# ---------- Subsystem ----------
class Subsystem:
    def __init__(self, name, kms):
        self.name = name
        self.kms = kms
        # Register and receive RSA + DH parameters
        self.rsa_private_key, self.dh_params = 
kms.register_subsystem(name)
    def initiate_secure_channel(self):
        logging.info(f"{self.name}: Initiating secure channel")
        # Generate DH key pair
        self.dh_private = self.dh_params.generate_private_key()
        dh_public = self.dh_private.public_key()
        # Serialize DH public key for signing
        dh_bytes = dh_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Sign DH public key → proves identity
        signature = self.rsa_private_key.sign(
            dh_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


        return dh_public, signature
    def receive_secure_channel(self, sender_name, sender_dh_public, 
sender_signature):
        logging.info(f"{self.name}: Receiving request from 
{sender_name}")
        # Get sender's RSA public key from KMS
        sender_public_key = self.kms.get_public_key(sender_name)
        sender_dh_bytes = sender_dh_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Verify signature → prevents impersonation
        try:
            sender_public_key.verify(
                sender_signature,
                sender_dh_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logging.info(f"{self.name}: Identity VERIFIED")
        except Exception:
            logging.error("Verification FAILED")
            return None, None
        # Generate own DH key
        self.dh_private = self.dh_params.generate_private_key()
        dh_public = self.dh_private.public_key()
        # Compute shared secret
        shared_secret = self.dh_private.exchange(sender_dh_public)
        logging.info(f"{self.name}: Shared secret computed\n")
        return dh_public, shared_secret
    def finalize_shared_secret(self, peer_dh_public):
        return self.dh_private.exchange(peer_dh_public)
# ---------- Simulation ----------
kms = KeyManagementSystem()
finance = Subsystem("Finance_System_A", kms)
hr = Subsystem("HR_System_B", kms)


# Step 1: Finance initiates
f_dh_pub, f_sig = finance.initiate_secure_channel()
# Step 2: HR verifies + responds
h_dh_pub, hr_secret = hr.receive_secure_channel("Finance_System_A", 
f_dh_pub, f_sig)
# Step 3: Finance computes shared secret
finance_secret = finance.finalize_shared_secret(h_dh_pub)
# ---------- Verification ----------
print("\nShared Secret Match:", finance_secret == hr_secret)
print("Secure Channel Established Successfully!")
2026-03-31 18:09:25,750 - INFO - KMS: Generating shared DH 
parameters...
2026-03-31 18:10:08,780 - INFO - KMS: Ready.
2026-03-31 18:10:09,076 - INFO - KMS: Registered Finance_System_A
2026-03-31 18:10:09,292 - INFO - KMS: Registered HR_System_B
2026-03-31 18:10:09,297 - INFO - Finance_System_A: Initiating secure 
channel
2026-03-31 18:10:09,355 - INFO - HR_System_B: Receiving request from 
Finance_System_A
2026-03-31 18:10:09,365 - INFO - HR_System_B: Identity VERIFIED
2026-03-31 18:10:09,407 - INFO - HR_System_B: Shared secret computed
Shared Secret Match: True
Secure Channel Established Successfully!
Question 2
HealthCare Inc., a leading healthcare provider, has implemented a secure patient data 
management system using the Rabin cryptosystem. The system allows authorized healthcare 
professionals to securely access and manage patient records across multiple hospitals and 
clinics within the organization. Implement a Python-based centralized key management service 
that can:
•
Key Generation: Generate public and private key pairs for each hospital and clinic using 
the Rabin cryptosystem. The key size should be configurable (e.g., 1024 bits).
•
Key Distribution: Provide a secure API for hospitals and clinics to request and receive 
their public and private key pairs.
•
Key Revocation: Implement a process to revoke and update the keys of a hospital or clinic 
when necessary (e.g., when a facility is closed or compromised).
•
Key Renewal: Automatically renew the keys of all hospitals and clinics at regular intervals 
(e.g., every 12 months) to maintain the security of the patient data management system.


•
Secure Storage: Securely store the private keys of all hospitals and clinics, ensuring that 
they are not accessible to unauthorized parties.
•
Auditing and Logging: Maintain detailed logs of all key management operations, such as 
key generation, distribution, revocation, and renewal, to enable auditing and compliance 
reporting.
•
Regulatory Compliance: Ensure that the key management service and its operations are 
compliant with relevant data privacy regulations (e.g., HIPAA).
•
Perform a trade-off analysis to compare the workings of Rabin and RSA.
# ---------- Imports ----------
import logging
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - KMS 
Audit - %(message)s')
# ---------- Rabin KMS ----------
class RabinKMS:
    def __init__(self, key_size=512):
        self.key_size = key_size
        self._secure_vault = {}      # Stores private keys securely
        self.public_registry = {}    # Stores public keys
        logging.info("Rabin KMS Initialized (Secure Mode)")
    # Generate primes p ≡ 3 mod 4 → simplifies square root during 
decryption
    def _generate_rabin_keypair(self):
        while True:
            p = getPrime(self.key_size // 2)
            if p % 4 == 3:
                break
        while True:
            q = getPrime(self.key_size // 2)
            if q % 4 == 3 and q != p:
                break
        n = p * q
        return (n,), (p, q)
    def generate_and_distribute(self, facility_id):
        pub_key, priv_key = self._generate_rabin_keypair()
        self._secure_vault[facility_id] = priv_key
        self.public_registry[facility_id] = {
            'pub_key': pub_key,
            'status': 'ACTIVE'


        }
        logging.info(f"Generated keys for {facility_id}")
        return pub_key
    def revoke_key(self, facility_id, reason="Compromised"):
        if facility_id in self.public_registry:
            self.public_registry[facility_id]['status'] = 'REVOKED'
            self._secure_vault.pop(facility_id, None)
            logging.warning(f"Revoked {facility_id} → Reason: 
{reason}")
    def renew_keys(self):
        logging.info("Starting key renewal...")
        for facility_id in list(self.public_registry.keys()):
            if self.public_registry[facility_id]['status'] == 
'ACTIVE':
                self.generate_and_distribute(facility_id)
        logging.info("Key renewal complete.\n")
# ---------- Rabin Encryption ----------
def rabin_encrypt(message_bytes, public_key):
    n = public_key[0]
    # Convert message → integer
    m = bytes_to_long(message_bytes)
    # Rabin encryption: m^2 mod n
    return pow(m, 2, n)
# ---------- Demonstration ----------
kms = RabinKMS(key_size=512)
# Generate keys
hospital_pub = kms.generate_and_distribute("Hospital_A")
clinic_pub = kms.generate_and_distribute("Clinic_B")
# Encrypt patient data
patient_data = b"Patient ID: 9942, Condition: Stable"
ciphertext = rabin_encrypt(patient_data, hospital_pub)
print("\nEncrypted Data (Integer):", ciphertext)
# Revoke a facility
kms.revoke_key("Clinic_B", reason="Facility Closed")
# Renew keys
kms.renew_keys()


2026-03-31 18:10:09,600 - INFO - Rabin KMS Initialized (Secure Mode)
2026-03-31 18:10:12,204 - INFO - Generated keys for Hospital_A
2026-03-31 18:10:12,572 - INFO - Generated keys for Clinic_B
2026-03-31 18:10:12,581 - WARNING - Revoked Clinic_B → Reason: 
Facility Closed
2026-03-31 18:10:12,587 - INFO - Starting key renewal...
Encrypted Data (Integer): 
5728085830732477177301703313109634153750990639612109876182465046795105
5878282168414496825003536963985236168572746691170086575407927086012272
01828409336103
2026-03-31 18:10:13,387 - INFO - Generated keys for Hospital_A
2026-03-31 18:10:13,413 - INFO - Key renewal complete.
Additional Questions
Question 1
DigiRights Inc. is a leading provider of digital content, including e-books, movies, and music. The 
company has implemented a secure digital rights management (DRM) system using the ElGamal 
cryptosystem to protect its valuable digital assets.
Implement a Python-based centralized key management and access control service that can:
•
Key Generation: Generate a master public-private key pair using the ElGamal 
cryptosystem. The key size should be configurable (e.g., 2048 bits).
•
Content Encryption: Provide an API for content creators to upload their digital content 
and have it encrypted using the master public key.
•
Key Distribution: Manage the distribution of the master private key to authorized 
customers, allowing them to decrypt the content.
•
Access Control: Implement flexible access control mechanisms, such as:
–
Granting limited-time access to customers for specific content
–
Revoking access to customers for specific content
–
Allowing content creators to manage access to their own content
•
Key Revocation: Implement a process to revoke the master private key in case of a 
security breach or other emergency.
•
Key Renewal: Automatically renew the master public-private key pair at regular intervals 
(e.g., every 24 months) to maintain the security of the DRM system.
•
Secure Storage: Securely store the master private key, ensuring that it is not accessible to 
unauthorized parties.
•
Auditing and Logging: Maintain detailed logs of all key management and access control 
operations to enable auditing and troubleshooting.
# ---------- Imports ----------
import logging
import random


import time
from Crypto.Util.number import getPrime
# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - DRM 
Audit - %(message)s')
# ---------- DRM System ----------
class DigiRightsDRM:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self._master_private_key = None
        self.master_public_key = None
        self.access_control_list = {}
        self.content_store = {}
        self._generate_master_keys()
    # ---------- Key Generation ----------
    def _generate_master_keys(self):
        logging.info("Generating ElGamal Master Keys...")
        
        p = getPrime(self.key_size)
        g = 2
        x = random.randint(2, p - 2)   # private key
        y = pow(g, x, p)               # public component
        
        self.master_public_key = (p, g, y)
        self._master_private_key = x
        
        logging.info("Master keys generated and securely stored.")
    # ---------- Content Encryption ----------
    def encrypt_content(self, content_id, content_data):
        p, g, y = self.master_public_key
        # Step 1: Generate symmetric key (simulated)
        symmetric_key = random.randint(1, p - 1)
        # Step 2: Encrypt symmetric key using ElGamal
        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
        c2 = (symmetric_key * pow(y, k, p)) % p
        # Step 3: Encrypt content (simple XOR simulation)
        encrypted_content = bytes([b ^ (symmetric_key % 256) for b in 
content_data])
        # Store encrypted content


        self.content_store[content_id] = {
            'cipher': (c1, c2),
            'data': encrypted_content
        }
        # Initialize access control
        self.access_control_list[content_id] = set()
        logging.info(f"Content '{content_id}' encrypted and stored.")
    # ---------- Grant Access ----------
    def grant_access(self, content_id, user_id):
        self.access_control_list[content_id].add(user_id)
        logging.info(f"Access granted → User: {user_id}, Content: 
{content_id}")
    # ---------- Revoke Access ----------
    def revoke_access(self, content_id, user_id):
        self.access_control_list[content_id].discard(user_id)
        logging.warning(f"Access revoked → User: {user_id}, Content: 
{content_id}")
    # ---------- Decrypt Content ----------
    def decrypt_content(self, content_id, user_id):
        if user_id not in self.access_control_list[content_id]:
            raise PermissionError("Access Denied!")
        p, g, y = self.master_public_key
        x = self._master_private_key
        c1, c2 = self.content_store[content_id]['cipher']
        # Recover symmetric key
        s = pow(c1, x, p)
        s_inv = pow(s, p - 2, p)
        symmetric_key = (c2 * s_inv) % p
        encrypted_data = self.content_store[content_id]['data']
        # Decrypt content
        decrypted = bytes([b ^ (symmetric_key % 256) for b in 
encrypted_data])
        return decrypted
    # ---------- Key Revocation ----------
    def revoke_master_key(self):
        logging.warning("Master key revoked due to security breach!")
        self._generate_master_keys()


    # ---------- Key Renewal ----------
    def renew_keys(self):
        logging.info("Renewing master keys...")
        self._generate_master_keys()
# ---------- Demonstration ----------
drm = DigiRightsDRM(key_size=512)
# Content upload
content_id = "Movie_001"
content_data = b"Top Secret Movie Data"
drm.encrypt_content(content_id, content_data)
# Grant access
drm.grant_access(content_id, "User_A")
# Decrypt content
decrypted = drm.decrypt_content(content_id, "User_A")
print("\nDecrypted Content:", decrypted.decode())
# Revoke access
drm.revoke_access(content_id, "User_A")
# Key renewal
drm.renew_keys()
2026-03-31 18:10:13,637 - INFO - Generating ElGamal Master Keys...
2026-03-31 18:10:13,878 - INFO - Master keys generated and securely 
stored.
2026-03-31 18:10:13,910 - INFO - Content 'Movie_001' encrypted and 
stored.
2026-03-31 18:10:13,914 - INFO - Access granted → User: User_A, 
Content: Movie_001
2026-03-31 18:10:13,936 - WARNING - Access revoked → User: User_A, 
Content: Movie_001
2026-03-31 18:10:13,945 - INFO - Renewing master keys...
2026-03-31 18:10:13,949 - INFO - Generating ElGamal Master Keys...
Decrypted Content: Top Secret Movie Data
2026-03-31 18:10:14,244 - INFO - Master keys generated and securely 
stored.
Question 2
Suppose that XYZ Logistics has decided to use the RSA cryptosystem to secure their sensitive 
communications. However, the security team at XYZ Logistics has discovered that one of their 


employees, Eve, has obtained a partial copy of the RSA private key and is attempting to recover 
the full private key to decrypt the company's communications.
Eve's attack involves exploiting a vulnerability in the RSA key generation process, where the 
prime factors (p and q) used to generate the modulus (n) are not sufficiently large or random.
Develop a Python script that can demonstrate the attack on the vulnerable RSA cryptosystem 
and discuss the steps to mitigate the attack.
# ---------- Imports ----------
import math
# ---------- Step 1: Generate Weak RSA Modulus ----------
def generate_vulnerable_rsa():
    # p and q are very close → vulnerable
    p = 100000000003
    q = 100000000019
    n = p * q
    return n, p, q
# ---------- Step 2: Fermat Factorization ----------
def fermat_factorization(n):
    """
    Works efficiently when p ≈ q.
    Finds n = a^2 - b^2 = (a - b)(a + b)
    """
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    while True:
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            return int(p), int(q)
        a += 1
# ---------- Step 3: Demonstration ----------
print("\n--- RSA Vulnerability Demonstration ---\n")
n, actual_p, actual_q = generate_vulnerable_rsa()
print(f"Public Modulus (n): {n}")


print("Eve only knows 'n'...\n")
print("Running Fermat Factorization Attack...")
cracked_p, cracked_q = fermat_factorization(n)
print(f"\nCracked p: {cracked_p}")
print(f"Cracked q: {cracked_q}")
# ---------- Step 4: Verification ----------
if (cracked_p == actual_p and cracked_q == actual_q) or \
   (cracked_p == actual_q and cracked_q == actual_p):
    print("\n[ALERT] Attack Successful!")
    print("Eve can now compute private key and decrypt all 
communications.")
else:
    print("\nAttack failed (unexpected case)")
--- RSA Vulnerability Demonstration ---
Public Modulus (n): 10000000002200000000057
Eve only knows 'n'...
Running Fermat Factorization Attack...
Cracked p: 100000000003
Cracked q: 100000000019
[ALERT] Attack Successful!
Eve can now compute private key and decrypt all communications.
```
