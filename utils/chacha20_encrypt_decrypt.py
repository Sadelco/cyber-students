import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
#from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key_nonce():
    key = os.urandom(32)  # ChaCha20 requires a 256-bit key
    nonce = os.urandom(16)  # Nonce should be 16 bytes for ChaCha20
    return key, nonce

# Encryption function
def encrypt(plaintext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext_bytes = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return ciphertext_bytes.hex()

# Decryption function
def decrypt(ciphertext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    plaintext_bytes = decryptor.update(bytes.fromhex(ciphertext)) + decryptor.finalize()
    return plaintext_bytes.decode()

# one hash function for hashing stored password
def hash_password(password):
# Decided to use SHA-256 without salt for the purpose of this assessment
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password











#def hash_password(password, salt=None):
    #if salt is None:
        #salt = os.urandom(16)  # Generate a new salt if not provided
    #kdf = PBKDF2HMAC(
        #algorithm=hashes.SHA256(),
        #length=32,
        #salt=salt,
        #iterations=100000,
        #backend=default_backend()
    #)
    #hashed_password = kdf.derive(password.encode())
    #return hashed_password.hex(), salt.hex()  # Return hexadecimal representations


# Example usage:
# key, nonce = generate_key_nonce()
# ciphertext = encrypt("secretkey", key, nonce)
# print("Ciphertext:", ciphertext)
# plaintext = decrypt(ciphertext, key, nonce)
# print("Original Plaintext:", plaintext)

