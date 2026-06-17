import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.exceptions import InvalidSignature


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)    #genera chiave privata 
    return private_key, private_key.public_key()


def generate_symmetric_key() -> bytes:
    return os.urandom(32)       #genera chiave simmetrica a 32byte


def generate_nonce() -> bytes:
    return os.urandom(16)       # genera nonce casuale a 16byte


# Definizione padding OAEP
_OAEP = asym_padding.OAEP(
    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(plaintext, _OAEP)     # cifra  il testo con la chiave pubblica e RSA-OAEP


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, _OAEP)   # decifra  il testo con la chiave privata e RSA-OAEP


# Definizione padding PSS per le firme
_PSS = asym_padding.PSS(
    mgf=asym_padding.MGF1(hashes.SHA256()),
    salt_length=asym_padding.PSS.MAX_LENGTH,
)

def rsa_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message, _PSS, hashes.SHA256())     # firma message con chiave privata di chi firma e con RSA-PSS


def rsa_verify(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, _PSS, hashes.SHA256())    #verifica la firma con la chiave pubblica di chi ha firmato
        return True
    except InvalidSignature:
        return False

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())     # calcola hmac
    h.update(message)                       # combina hmac con message ottenendo il tag 
    return h.finalize()                     # ritorna il tag 


def hmac_verify(key: bytes, message: bytes, tag: bytes) -> bool:
    
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(tag)   # ricalcola l'HMAC sul messaggio e lo confronta con tag
        return True
    except InvalidSignature:
        return False

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def public_key_to_bytes(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
