from dataclasses import dataclass

from crypto_primitives import (
    generate_rsa_keypair,
    rsa_sign,
    rsa_verify,
    public_key_to_bytes,
)


@dataclass
class Certificate:
    subject: str          # identita' del soggetto (es. "AE", "AA", "elettore_03")
    public_key: object    # chiave pubblica RSA del soggetto
    signature: bytes      # firma della CA su (subject ‖ public_key_PEM)

    def _signed_payload(self) -> bytes:
        return self.subject.encode("utf-8") + b"|" + public_key_to_bytes(self.public_key)


class CertificationAuthority:
    def __init__(self):
        self._private_key, self.public_key = generate_rsa_keypair()     # la CA genera le proprie chiavi 

    def issue_certificate(self, subject: str, subject_public_key) -> Certificate:
        cert = Certificate(subject=subject, public_key=subject_public_key, signature=b"")   # crea certificato per identità senza firma
        cert.signature = rsa_sign(self._private_key, cert._signed_payload())        # aggiunge la firma
        return cert             # ritorna certificato firmato

    def verify_certificate(self, cert: Certificate) -> bool:
        return rsa_verify(self.public_key, cert.signature, cert._signed_payload())  #verifica firma CA sul ceritficato
