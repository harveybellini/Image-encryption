import os
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_image(image_file, password):
    # Generate a salt
    salt = os.urandom(16)

    # Derive the key and initialization vector using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        salt=salt,
        length=32+16,
        backend=default_backend()
    )
    key_iv = kdf.derive(password)
    key = key_iv[:32]
    iv = key_iv[32:]

    # Read the image file
    with open(image_file, 'rb') as f:
        plaintext = f.read()

    # Encrypt the plaintext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write the salt and ciphertext to a new file
    with open(image_file + '.enc', 'wb') as f:
        f.write(salt)
        f.write(ciphertext)
