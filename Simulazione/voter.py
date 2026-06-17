from crypto_primitives import (
    generate_symmetric_key,
    sha256_hex,
    rsa_encrypt,
    hmac_sha256,
)
from bulletin_board import VoteRecord


class Voter:

    def __init__(self, voter_id: str):
        self.voter_id = voter_id
        self.token = None            # assegnato dalla registrazione presso l'AA
        self._k_mac = None           # chiave di integrita' generata dall'elettore
        self._my_record = None       # foglia inviata, per la verifica individuale

    def obtain_token(self, registration_authority) -> None:
        self._k_mac = generate_symmetric_key()      #genera h_mac
        fingerprint = sha256_hex(self._k_mac)       #calcola impronta SHA-256
        self.token = registration_authority.register_and_issue_token(
            self.voter_id, fingerprint              #invia impronta all'AA
        )

    def prepare_ballot(self, vote: str, ae_public_key, nonce: bytes) -> tuple:
        
        if self.token is None or self._k_mac is None:
            raise RuntimeError("L'elettore non e' registrato: ottenere prima il token dall'AA")
        if vote not in {"SI", "NO"}:
            raise ValueError("Il voto deve essere 'SI' o 'NO'")

        c_hex = rsa_encrypt(ae_public_key, vote.encode("utf-8")).hex()  # crea cifrato

        k_enc = rsa_encrypt(ae_public_key, self._k_mac)                 # crea chiave cifrata

        transit_message = (c_hex + "|" + self.token.pseudonym + "|" + nonce.hex()).encode("utf-8")
        tag_hex = hmac_sha256(self._k_mac, transit_message).hex()       # crea tag

        self._my_record = VoteRecord(c=c_hex, tag=tag_hex, token=self.token.pseudonym)
        return c_hex, tag_hex, self.token, k_enc            # definisce la foglia che si salva sul BB

    def verify_individual(self, bulletin_board) -> bool:
        if self._my_record is None:
            raise RuntimeError("Nessuna scheda inviata da verificare")
        proof = bulletin_board.get_inclusion_proof(self._my_record)
        return bulletin_board.verify_inclusion(self._my_record, proof, bulletin_board.merkle_root)
