import secrets

PRIME = 2**521 - 1


def _eval_poly(coeffs: list[int], x: int, p: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p         # metodo Horner
    return acc


def split_secret(secret_int: int, t: int, n: int, p: int = PRIME) -> list[tuple[int, int]]:
    if not (0 < t <= n):
        raise ValueError("Deve valere 0 < t <= n")
    if secret_int >= p:
        raise ValueError("Il segreto deve essere minore del primo p")

    coeffs = [secret_int] + [secrets.randbelow(p) for _ in range(t - 1)]        
    return [(i, _eval_poly(coeffs, i, p)) for i in range(1, n + 1)]         # genera le quote


def _inverse_mod(a: int, p: int) -> int:
    return pow(a, p - 2, p)     # Inverso moltiplicativo (Fermat)

# Ricostruisce il segreto
def recover_secret(shares: list[tuple[int, int]], p: int = PRIME) -> int:
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        num, den = 1, 1
        for m, (xm, _) in enumerate(shares):
            if m == j:
                continue
            num = (num * (-xm)) % p
            den = (den * (xj - xm)) % p
        lagrange = (num * _inverse_mod(den, p)) % p
        secret = (secret + yj * lagrange) % p
    return secret % p
