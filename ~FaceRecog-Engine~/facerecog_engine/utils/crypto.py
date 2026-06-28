import io
import os
import json
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from facerecog_engine.exceptions import CryptoError

def _derive_key(passphrase: str, salt: bytes, iterations: int = 100_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt_data(data: bytes, passphrase: str, iterations: int = 100_000) -> bytes:
    """Encrypt byte data using AES-256-GCM with PBKDF2 key derivation."""
    try:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_key(passphrase, salt, iterations)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return salt + nonce + ciphertext
    except Exception as e:
        raise CryptoError("Encryption failed.") from e

def decrypt_data(encrypted_data: bytes, passphrase: str, iterations: int = 100_000) -> bytes:
    """Decrypt byte data using AES-256-GCM."""
    if len(encrypted_data) < 28:
        raise CryptoError("Ciphertext is too short.")
    
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]
    
    try:
        key = _derive_key(passphrase, salt, iterations)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise CryptoError("Decryption failed. Invalid passphrase or corrupted data.") from e

def encrypt_embeddings(embeddings: np.ndarray, passphrase: str, iterations: int = 100_000) -> bytes:
    """Serialize and encrypt numpy embeddings array."""
    try:
        buffer = io.BytesIO()
        np.save(buffer, embeddings)
        raw_bytes = buffer.getvalue()
        return encrypt_data(raw_bytes, passphrase, iterations)
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError("Failed to encrypt embeddings.") from e

def decrypt_embeddings(encrypted_data: bytes, passphrase: str, iterations: int = 100_000) -> np.ndarray:
    """Decrypt and deserialize numpy embeddings array."""
    try:
        raw_bytes = decrypt_data(encrypted_data, passphrase, iterations)
        buffer = io.BytesIO(raw_bytes)
        return np.load(buffer, allow_pickle=False)
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError("Failed to decrypt embeddings.") from e

def encrypt_enrollment_record(record: dict, passphrase: str, iterations: int = 100_000) -> bytes:
    """Serialize to JSON and encrypt enrollment record dictionary."""
    try:
        json_bytes = json.dumps(record).encode('utf-8')
        return encrypt_data(json_bytes, passphrase, iterations)
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError("Failed to encrypt enrollment record.") from e

def decrypt_enrollment_record(encrypted_data: bytes, passphrase: str, iterations: int = 100_000) -> dict:
    """Decrypt and parse enrollment record dictionary."""
    try:
        json_bytes = decrypt_data(encrypted_data, passphrase, iterations)
        return json.loads(json_bytes.decode('utf-8'))
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise CryptoError("Failed to decrypt enrollment record.") from e
