from Crypto.Cipher import AES, ChaCha20, Salsa20
import serpent
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import os
from json import dumps, loads

def derive_key(password, salt, key_len=32):
    """Derives a key using scrypt based on password and salt"""
    return scrypt(password.encode(), salt=salt, key_len=key_len, N=2**14, r=8, p=1)

def encrypt_file(input_path, output_path, password, algorithm):
    """Encrypts the file using specified algorithm (AES, ChaCha20, Serpent, or Salsa20)"""
    salt = get_random_bytes(16)
    key = derive_key(password, salt)

    with open(input_path, 'rb') as f:
        data = f.read()

    if algorithm == 'AES':
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padding = 16 - (len(data) % 16)
        data += bytes([padding]) * padding
        ciphertext = cipher.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(b'AES' + salt + iv + ciphertext)
    elif algorithm == 'ChaCha20':
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(b'CHC' + salt + nonce + ciphertext)
    elif algorithm == 'Serpent':  # Replacing Camellia with Serpent
        iv = get_random_bytes(16)
        cipher = serpent.new(key, serpent.MODE_CBC, iv)
        padding = 16 - (len(data) % 16)
        data += bytes([padding]) * padding
        ciphertext = cipher.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(b'SRP' + salt + iv + ciphertext)  # Using 'SRP' as prefix
    elif algorithm == 'Salsa20':
        nonce = get_random_bytes(8)
        cipher = Salsa20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(b'SAL' + salt + nonce + ciphertext)

def decrypt_file(input_path, output_path, password, algorithm):
    """Decrypts the file using specified algorithm (AES, ChaCha20, Serpent, or Salsa20)"""
    with open(input_path, 'rb') as f:
        prefix = f.read(3)
        salt = f.read(16)
        key = derive_key(password, salt)

        if prefix == b'AES':
            iv = f.read(16)
            ciphertext = f.read()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            data = cipher.decrypt(ciphertext)
            padding_len = data[-1]
            data = data[:-padding_len]
        elif prefix == b'CHC':
            nonce = f.read(8)
            ciphertext = f.read()
            cipher = ChaCha20.new(key=key, nonce=nonce)
            data = cipher.decrypt(ciphertext)
        elif prefix == b'SRP':  # Replacing Camellia with Serpent
            iv = f.read(16)
            ciphertext = f.read()
            cipher = serpent.new(key, serpent.MODE_CBC, iv)
            data = cipher.decrypt(ciphertext)
            padding_len = data[-1]
            data = data[:-padding_len]
        elif prefix == b'SAL':
            nonce = f.read(8)
            ciphertext = f.read()
            cipher = Salsa20.new(key=key, nonce=nonce)
            data = cipher.decrypt(ciphertext)
        else:
            raise ValueError("Unsupported algorithm or invalid file format")

    with open(output_path, 'wb') as f:
        f.write(data)

def encrypt_data(data: dict) -> bytes:
    """Encrypts a dictionary using AES encryption"""
    key = derive_key("admin-password", b"admin-salt")
    cipher = AES.new(key, AES.MODE_CBC)
    raw = dumps(data).encode()
    padded = raw + (16 - len(raw) % 16) * bytes([16 - len(raw) % 16])
    return cipher.iv + cipher.encrypt(padded)

def decrypt_data(enc: bytes) -> dict:
    """Decrypts data back into a dictionary"""
    key = derive_key("admin-password", b"admin-salt")
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(enc[16:])
    return loads(data.rstrip(data[-1:].decode('latin1').encode()))

def save_encrypted_data(data: dict, filename: str):
    """Saves encrypted data to a file"""
    with open(filename, 'wb') as f:
        f.write(encrypt_data(data))

def load_encrypted_data(filename: str) -> dict:
    """Loads and decrypts data from a file"""
    with open(filename, 'rb') as f:
        return decrypt_data(f.read())