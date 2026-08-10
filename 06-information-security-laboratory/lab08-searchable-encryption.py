"""
Lab 08: Searchable Symmetric Encryption (SSE)
Building a Searchable Encrypted Inverted Index and Trapdoor Queries.
"""

import hashlib
import hmac

class SearchableSymmetricEncryption:
    def __init__(self, key: bytes):
        self.key = key
        self.encrypted_index = {}

    def _trapdoor(self, keyword: str) -> str:
        return hmac.new(self.key, keyword.lower().encode('utf-8'), hashlib.sha256).hexdigest()

    def build_index(self, documents: dict):
        for doc_id, text in documents.items():
            words = set(text.lower().split())
            for w in words:
                td = self._trapdoor(w)
                if td not in self.encrypted_index:
                    self.encrypted_index[td] = []
                self.encrypted_index[td].append(doc_id)

    def search(self, keyword: str) -> list:
        td = self._trapdoor(keyword)
        return self.encrypted_index.get(td, [])

if __name__ == "__main__":
    print("=== LAB 08: SEARCHABLE SYMMETRIC ENCRYPTION (SSE) DEMO ===")
    key = b"master_sse_key_12345"
    sse = SearchableSymmetricEncryption(key)

    docs = {
        "doc1": "the quick brown fox jumps over the lazy dog",
        "doc2": "information security and cryptography lab exercises",
        "doc3": "public key cryptography and searchable symmetric encryption"
    }

    sse.build_index(docs)

    res_crypto = sse.search("cryptography")
    res_fox = sse.search("fox")
    res_missing = sse.search("python")

    print(f"Search 'cryptography': {res_crypto}")
    print(f"Search 'fox'         : {res_fox}")
    print(f"Search 'python'      : {res_missing}")

    assert "doc2" in res_crypto and "doc3" in res_crypto, "SSE Search failed for 'cryptography'!"
    assert "doc1" in res_fox, "SSE Search failed for 'fox'!"
    assert len(res_missing) == 0, "SSE Search failed for missing term!"
    print("[SUCCESS] All Lab 08 functions executed clean!")
