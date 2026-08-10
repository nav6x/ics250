"""
Lab 05: Cryptographic Hash Functions & Message Authentication Codes (MAC)
SHA-1, SHA-256, MD5, and HMAC-SHA256.
"""

import hashlib
import hmac

def hash_comparison(message: str):
    md5_digest = hashlib.md5(message.encode('utf-8')).hexdigest()
    sha1_digest = hashlib.sha1(message.encode('utf-8')).hexdigest()
    sha256_digest = hashlib.sha256(message.encode('utf-8')).hexdigest()
    return md5_digest, sha1_digest, sha256_digest

def compute_hmac(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest()

def verify_hmac(key: bytes, message: str, expected_tag: str) -> bool:
    actual_tag = compute_hmac(key, message)
    return hmac.compare_digest(actual_tag, expected_tag)

if __name__ == "__main__":
    print("=== LAB 05: HASH FUNCTIONS & HMAC DEMO ===")
    msg = "CONFIDENTIAL FINANCIAL TRANSACTION PAYLOAD"
    key = b"secret_shared_hmac_key_99"

    md5_d, sha1_d, sha256_d = hash_comparison(msg)
    tag = compute_hmac(key, msg)
    is_valid = verify_hmac(key, msg, tag)

    print(f"Message       : '{msg}'")
    print(f"MD5 Digest    : {md5_d}")
    print(f"SHA-1 Digest  : {sha1_d}")
    print(f"SHA-256 Digest: {sha256_d}")
    print(f"HMAC-SHA256   : {tag}")
    print(f"HMAC Valid    : {is_valid}")
    assert is_valid, "HMAC Verification failed!"
    print("[SUCCESS] All Lab 05 functions executed clean!")
