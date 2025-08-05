import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher
from argon2.low_level import Type, hash_secret_raw
from argon2.exceptions import VerifyMismatchError

ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 131072  # 128 MB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32

ph = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    type=Type.ID,
)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hashed: str, password: str) -> bool:
    try:
        return ph.verify(hashed, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False

def derive_encryption_key(password: str, salt: bytes) -> bytes:
    raw_key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file-encryption-key',
    )
    return hkdf.derive(raw_key)

def encrypt_file_data(data: bytes, password: str, associated_data: bytes = b'') -> bytes:
    version = b'\x01'
    salt = os.urandom(16)
    key = derive_encryption_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)
    return version + salt + nonce + ciphertext

def decrypt_file_data(enc_data: bytes, password: str, associated_data: bytes = b'') -> bytes | None:
    try:
        if len(enc_data) < 1 + 16 + 12:
            return None

        version = enc_data[0]
        if version != 1:
            return None

        salt = enc_data[1:17]
        nonce = enc_data[17:29]
        ciphertext = enc_data[29:]

        key = derive_encryption_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception:
        return None