import hashlib


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def build_merkle_tree(data_list: list[str]) -> tuple[str, list[list[str]]]:
    if not data_list:
        raise ValueError("data_list non puo' essere vuota")

    tree = [[sha256(d) for d in data_list]]

    while len(tree[-1]) > 1:        #continua a salire finchè l'ultimo livello ha più di un nodo
        level = tree[-1]            
        if len(level) % 2 == 1:          # il livello deve avere nodi pari
            level = level + [level[-1]]  # duplica l'ultimo nodo se il livello e' dispari

        tree.append([
            sha256(level[i] + level[i + 1])     # Padre è hash della concatenazione dei due figli
            for i in range(0, len(level), 2)    
        ])

    return tree[-1][0], tree        # ritorna radice e albero


def generate_proof(leaf_index: int, tree: list[list[str]]) -> list[tuple[str, str]]:
    
    proof = []
    index = leaf_index      #partiamo dalla foglia

    for level in tree[:-1]:         # saliamo tutto l albero fino al figlio della radice
        if len(level) % 2 == 1:     # i nodi devono essere pari perchè il padre è sempre concatenazione di 2 figli
            level = level + [level[-1]]

        # Verifica se il fratello del nodo è a dx o sx
        sibling_index = index ^ 1       
        position = "right" if sibling_index > index else "left"
        proof.append((position, level[sibling_index]))
        index //= 2

    return proof


def verify_proof(data: str, proof: list[tuple[str, str]], root: str) -> bool:
    current = sha256(data)  # si parte dalla foglia

    # se il fratello è a dx il nodo va a sx e viceversa (l'ordine di concatenazione è importante)
    for position, sibling in proof:
        if position == "right":
            current = sha256(current + sibling)
        else:
            current = sha256(sibling + current)

    return current == root
