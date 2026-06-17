from dataclasses import dataclass, field

from merkle import build_merkle_tree, generate_proof, verify_proof
from crypto_primitives import rsa_verify


@dataclass
class VoteRecord:
    c: str
    tag: str
    token: str

    def serialize(self) -> str:
        return f"{self.c}|{self.tag}|{self.token}"  #rappresenta foglia di Merkle


@dataclass
class BulletinBoard:
    records: list[VoteRecord] = field(default_factory=list)
    merkle_root: str = ""
    root_signature: bytes = b""

    def append(self, record: VoteRecord) -> None:
        self.records.append(record)             # aggiunta foglia 

    def publish_root(self, ae_private_key, rsa_sign_fn) -> None:
        leaves = [r.serialize() for r in self.records]      # prende tutte le foglie
        self.merkle_root, self._tree = build_merkle_tree(leaves)        # costruisce albero Merkle e calcola radice
        self.root_signature = rsa_sign_fn(ae_private_key, self.merkle_root.encode("utf-8")) #firma radice con ae_private_key

    def verify_published_root(self, ae_public_key) -> bool:
        leaves = [r.serialize() for r in self.records]  # prende tutte le foglie
        recomputed_root, _ = build_merkle_tree(leaves)  # scarta albero completo e prende solo la radice
        if recomputed_root != self.merkle_root:         # controlla che la radice calcolata ora coincida con la radice iniziale
            return False                                # se non coincide ritorna false perchè il voto è stato alterato
        return rsa_verify(ae_public_key, self.root_signature, self.merkle_root.encode("utf-8")) #se coincidono si verifica la firma dell ae


    def get_inclusion_proof(self, record: VoteRecord) -> list[tuple[str, str]]:
        leaves = [r.serialize() for r in self.records]  # prende tutte le foglie
        index = leaves.index(record.serialize())        # calcola indice della foglia corrente nella lista
        return generate_proof(index, self._tree)        # verifica che la foglia sia presente nell'albero

    @staticmethod
    def verify_inclusion(record: VoteRecord, proof, root: str) -> bool:
        return verify_proof(record.serialize(), proof, root)    # verifica che la foglia sia inclusa in BB
