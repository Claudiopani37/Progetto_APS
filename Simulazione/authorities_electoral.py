import os
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crypto_primitives import (
    generate_rsa_keypair,
    generate_nonce,
    rsa_decrypt,
    rsa_sign,
    hmac_verify,
    sha256_hex,
)
from bulletin_board import BulletinBoard, VoteRecord
import shamir


# Autorita' elettorale

class ElectoralAuthority:

    def __init__(self, bulletin_board: BulletinBoard, aa_public_key, aa_verify_token_fn, t: int, n: int):
        self._private_key, self.public_key = generate_rsa_keypair() # Coppia di chiavi RSA dell'AE.
        self.bb = bulletin_board
        self._aa_public_key = aa_public_key
        self._aa_verify_token = aa_verify_token_fn
        self._spent_tokens: set[str] = set()    # registro dei token gia' consumati, in modo da non consentire il doppio voto.
        self._open_nonces: set[str] = set()     # nonce di sessione emessi e non ancora usati.

        # Protezione della chiave privata dell'AE con Shamir (t,n) 
        self.t, self.n = t, n
        secret_int = int.from_bytes(os.urandom(32), "big") % shamir.PRIME # genera un numero casuale a 256 bit ridotto nel campo di Shamir.
        self._shares = shamir.split_secret(secret_int, t, n) # il numero casuale viene spezzato in n quote.

        aes_key = self._derive_aes_key(secret_int) # chiave AES-256.
        self._iv = os.urandom(16) # IV per AES-CTR: salvato perche' lo stesso valore serve alla Commissione per decifrare.
        pem = self._private_key.private_bytes(  # esporta la chiave privata RSA in byte.
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        enc = Cipher(algorithms.AES(aes_key), modes.CTR(self._iv)).encryptor() # cifra la chiave privata con AES.
        self._encrypted_privkey = enc.update(pem) + enc.finalize()

    @staticmethod
    def _derive_aes_key(secret_int: int) -> bytes:  # deriva una chiave AES-256 dal segreto Shamir tramite SHA-256.
        return hashlib.sha256(secret_int.to_bytes(66, "big")).digest()  # restituzione delle n quote Shamir da consegnare ai membri della Commissione di Scrutinio.

    def distribute_shares(self) -> list[tuple[int, int]]:
        return list(self._shares)

    # Votazione

    def open_session(self) -> bytes:
       
        nonce = generate_nonce()
        self._open_nonces.add(nonce.hex()) # registra il nonce come "emesso e non ancora usato".
        return nonce

    def collect_vote(self, c_hex: str, tag_hex: str, token, k_enc: bytes, nonce: bytes) -> bool:
       # registra la foglia solo se tutti i controlli passano.
        nonce_hex = nonce.hex()

        
        if nonce_hex not in self._open_nonces: # il nonce deve essere uno di quelli emessi dall'AE.
            return False

        
        if not self._aa_verify_token(token): # validita' del token tramite la firma dell'AA.
            return False

        
        if token.pseudonym in self._spent_tokens: # il token non deve essere gia' consumato.
            return False

        # neutralizza il riuso del token con una chiave diversa.
        try:
            k_mac = rsa_decrypt(self._private_key, k_enc)
        except Exception:
            return False
        if sha256_hex(k_mac) != token.key_fpr:
            return False

        # tag HMAC su (c ‖ token ‖ nonce) con la chiave appena decifrata.
        transit_message = (c_hex + "|" + token.pseudonym + "|" + nonce_hex).encode("utf-8")
        if not hmac_verify(k_mac, transit_message, bytes.fromhex(tag_hex)):
            return False

        # tutti i controlli superati: consuma token e nonce, registra la foglia.
        self._spent_tokens.add(token.pseudonym)
        self._open_nonces.discard(nonce_hex)
        self.bb.append(VoteRecord(c=c_hex, tag=tag_hex, token=token.pseudonym))
        return True

    def close_and_publish(self) -> None:
        self.bb.publish_root(self._private_key, rsa_sign)
        self._private_key = None   # rimozione del riferimento dopo la firma.


# Commissione di Scrutinio

@dataclass
class TallyResult:
    # contenitore per il conteggio si, no e schede non valide.
    si: int
    no: int
    invalid: int

    def __str__(self) -> str:
        return f"Si': {self.si} | No: {self.no} | schede non valide: {self.invalid}"


class ScrutinyCommission:

    VALID_VOTES = {"SI", "NO"}

    def __init__(self, electoral_authority: ElectoralAuthority):
        self._ae = electoral_authority
        self.t = electoral_authority.t

    def tally(self, bulletin_board: BulletinBoard,
              presented_shares: list[tuple[int, int]]) -> TallyResult:
       
        if len(presented_shares) < self.t: # spoglio, se ci sono meno di t quote il segreto non e' ricostruibile.
            raise PermissionError(
                f"Quote insufficienti: {len(presented_shares)} < soglia t={self.t}"
            )

        # Ricostruzione del segreto e derivazione della chiave AES.
        secret = shamir.recover_secret(presented_shares[: self.t])
        aes_key = ElectoralAuthority._derive_aes_key(secret)

        # Recupero della chiave privata dell'AE.
        dec = Cipher(algorithms.AES(aes_key), modes.CTR(self._ae._iv)).decryptor()
        pem = dec.update(self._ae._encrypted_privkey) + dec.finalize()
        try:
            ae_private_key = serialization.load_pem_private_key(pem, password=None)
        except Exception:
            raise PermissionError("Ricostruzione fallita: quote non valide")

        # Decifratura e conteggio.
        si = no = invalid = 0
        for record in bulletin_board.records:
            try:
                plaintext = rsa_decrypt(ae_private_key, bytes.fromhex(record.c)).decode("utf-8")
            except Exception:
                invalid += 1  # scheda non valida.
                continue
            if plaintext == "SI":
                si += 1
            elif plaintext == "NO":
                no += 1
            else:
                invalid += 1   # scheda registrata ma contenuto non interpretabile.

        return TallyResult(si=si, no=no, invalid=invalid)
