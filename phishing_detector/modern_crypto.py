import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.backends import default_backend

from .logger import Logger

def generate_sha256_hash(data):
    """
    Generates a SHA256 hash of the input data (URL).
    """
    Logger.crypto_modern("Generating SHA256 hash...")
    hasher = hashlib.sha256()
    hasher.update(data.encode('utf-8'))
    result = hasher.hexdigest()
    Logger.crypto_modern("SHA256 Hash Generated")
    return result

def aes_encrypt(plaintext, key_size=32):
    """
    Encrypts data using AES-256 in CBC mode. Returns the base64 encoded ciphertext + IV.
    """
    Logger.crypto_modern("Encrypting results using AES...")
    key = os.urandom(key_size)
    iv = os.urandom(16)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    Logger.crypto_modern("AES Encryption Successful")
    
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def rsa_generate_keys():
    """
    Generates an RSA keypair for digital signing.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_sign_data(private_key, data):
    """
    Signs data using RSA private key.
    """
    Logger.crypto_modern("Signing hash with RSA...")
    signature = private_key.sign(
        data.encode('utf-8'),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def rsa_verify_signature(public_key, signature, data):
    """
    Verifies an RSA signature.
    """
    Logger.crypto_modern("Verifying signature...")
    try:
        public_key.verify(
            signature,
            data.encode('utf-8'),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        Logger.crypto_modern("RSA Signature Verified")
        return True
    except Exception as e:
        Logger.error("RSA Signature Verification Failed!")
        return False
