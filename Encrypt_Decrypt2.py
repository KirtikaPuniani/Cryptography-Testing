from cryptography.fernet import Fernet
from KeyRotation import key_rotation
from KeyStorage import get_encrypt_key
from MasterKey import get_master_key


def decrypt_dek_with_master(key_id: str) -> bytes:
    """
    Uses master.key to decrypt the stored encrypted DEK
    """
    master_fernet = Fernet(get_master_key())

    entry = get_encrypt_key(key_id)
    encrypted_dek = entry["encrypted_key"].encode()

    dek = master_fernet.decrypt(encrypted_dek)
    return dek


def encrypt_data(plaintext: bytes):
    # Step 1: get active key id (rotation logic)
    key_id = key_rotation()

    # Step 2: get decrypted DEK using master key
    dek = decrypt_dek_with_master(key_id)

    # Step 3: use DEK to encrypt data
    data_fernet = Fernet(dek)
    ciphertext = data_fernet.encrypt(plaintext)

    return {
        "key_id": key_id,
        "ciphertext": ciphertext.decode()
    }


def decrypt_data(key_id: str, ciphertext: str):
    # Step 1: decrypt DEK using master key
    dek = decrypt_dek_with_master(key_id)

    # Step 2: decrypt data
    data_fernet = Fernet(dek)
    plaintext = data_fernet.decrypt(ciphertext.encode())

    return plaintext.decode()

payload = encrypt_data(b"Highly Sensitive Data")
print(payload)

plain = decrypt_data(payload["key_id"], payload["ciphertext"])
print(plain)