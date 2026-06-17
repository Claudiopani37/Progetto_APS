import secrets
from dataclasses import dataclass

from crypto_primitives import generate_rsa_keypair, rsa_sign, rsa_verify


@dataclass
class VotingToken:  # token pseudoanonimo emesso dall'AA per certificare il diritto al voto senza rivelare l'identita'.
    pseudonym: str
    key_fpr: str
    signature: bytes

    def signed_payload(self) -> bytes:
        return (self.pseudonym + "|" + self.key_fpr).encode("utf-8") # dati firmati dall'AA, pseudonimo + impronta della chiave.


class RegistrationAuthority: # autorita' di autenticazione.

    def __init__(self, eligible_voters: set[str]):
        self._private_key, self.public_key = generate_rsa_keypair() # chiavi RSA dell'AA.
        self._eligible = set(eligible_voters)        # elenco di chi ha diritto al voto.
        self._already_registered: set[str] = set()   # per vedere chi ha gia' ricevuto il token.

    def register_and_issue_token(self, voter_id: str, key_fingerprint: str) -> VotingToken:  # verifica di chi ha diritto al voto e se ha gia' avuto il token
        if voter_id not in self._eligible:
            raise PermissionError(f"'{voter_id}' non e' un avente diritto")
        if voter_id in self._already_registered:
            raise PermissionError(f"'{voter_id}' ha gia' ottenuto un token (unicita')")

        self._already_registered.add(voter_id) # segna l'elettore che e' già registrato

        # pseudonimo casuale a 128 bit: privo di informazione sull'identita'.
        pseudonym = secrets.token_hex(16)
         # viene creato il token e firmato con la chiave privata dell'AA.
        token = VotingToken(pseudonym=pseudonym, key_fpr=key_fingerprint, signature=b"")
        token.signature = rsa_sign(self._private_key, token.signed_payload())
        return token

    def verify_token(self, token: VotingToken) -> bool:
         # verifica la firma del token con la chiave pubblica dell'AA.
        return rsa_verify(self.public_key, token.signature, token.signed_payload())
