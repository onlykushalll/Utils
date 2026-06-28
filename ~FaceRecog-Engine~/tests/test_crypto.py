import numpy as np
import pytest
from facerecog_engine.exceptions import CryptoError
from facerecog_engine.utils.crypto import (
    encrypt_data,
    decrypt_data,
    encrypt_embeddings,
    decrypt_embeddings,
    encrypt_enrollment_record,
    decrypt_enrollment_record,
)

def test_data_encryption_decryption():
    plaintext = b"Super secret biometric credential payload."
    passphrase = "my-secure-master-password"
    
    # Successful roundtrip
    ciphertext = encrypt_data(plaintext, passphrase)
    assert ciphertext != plaintext
    
    decrypted = decrypt_data(ciphertext, passphrase)
    assert decrypted == plaintext

    # Wrong passphrase raises CryptoError
    with pytest.raises(CryptoError):
        decrypt_data(ciphertext, "wrong-password")

    # Corrupt data raises CryptoError
    corrupt_ciphertext = bytearray(ciphertext)
    corrupt_ciphertext[-1] ^= 0xFF  # flip the last byte
    with pytest.raises(CryptoError):
        decrypt_data(bytes(corrupt_ciphertext), passphrase)

    # Too short ciphertext raises CryptoError
    with pytest.raises(CryptoError):
        decrypt_data(b"too_short", passphrase)

def test_embeddings_encryption_decryption():
    # Make a dummy float32 512-dim embedding array
    np.random.seed(42)
    embeddings = np.random.randn(512).astype(np.float32)
    passphrase = "embedding-key-123"

    ciphertext = encrypt_embeddings(embeddings, passphrase)
    decrypted_embeddings = decrypt_embeddings(ciphertext, passphrase)

    # Check matches original array
    assert np.array_equal(embeddings, decrypted_embeddings)
    assert decrypted_embeddings.dtype == np.float32

    # Verify wrong passphrase fails
    with pytest.raises(CryptoError):
        decrypt_embeddings(ciphertext, "wrong-password")

def test_enrollment_record_encryption_decryption():
    record = {
        "UserSid": "S-1-5-21-12345678-12345678-12345678-1001",
        "EnrolledAt": "2026-06-28T12:00:00Z",
        "SuccessfulAuthCount": 42,
        "EmbeddedMetaData": {"version": "v1", "device": "camera_0"}
    }
    passphrase = "record-encryption-key"

    ciphertext = encrypt_enrollment_record(record, passphrase)
    decrypted_record = decrypt_enrollment_record(ciphertext, passphrase)

    assert decrypted_record == record

    # Verify wrong passphrase fails
    with pytest.raises(CryptoError):
        decrypt_enrollment_record(ciphertext, "wrong-password")
