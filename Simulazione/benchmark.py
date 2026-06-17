import os
import time
import statistics

from crypto_primitives import (
    generate_rsa_keypair, generate_symmetric_key, generate_nonce,
    rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify,
    hmac_sha256, hmac_verify, sha256_hex,
)
from authorities_registration import RegistrationAuthority
from authorities_electoral import ElectoralAuthority, ScrutinyCommission
from bulletin_board import BulletinBoard
from voter import Voter
import shamir


def _time_op(fn, repeats: int = 200) -> float: # cronometra l'operazione fn eseguendola piu' volte e restituisce il tempo medio in ms.
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return statistics.mean(samples)


def micro_benchmarks():  # misura il costo delle singole primitive crittografiche.
    print(" COSTO DELLE OPERAZIONI CRITTOGRAFICHE (ms, media su 200)")

    priv, pub = generate_rsa_keypair()
    vote = b"SI"
    c = rsa_encrypt(pub, vote)
    msg = c.hex().encode()
    sig = rsa_sign(priv, msg)
    k = generate_symmetric_key()
    tag = hmac_sha256(k, msg)
    # ogni lambda impacchetta un'operazione, passa l'operazione che poi esegue  _time_op puo'.
    print(f"  Generazione coppia RSA-2048 : {_time_op(lambda: generate_rsa_keypair(), 20):8.3f}")
    print(f"  Cifratura voto (RSA-OAEP)   : {_time_op(lambda: rsa_encrypt(pub, vote)):8.3f}")
    print(f"  Incapsulamento k_mac (OAEP) : {_time_op(lambda: rsa_encrypt(pub, k)):8.3f}")
    print(f"  Decifratura RSA-OAEP        : {_time_op(lambda: rsa_decrypt(priv, c)):8.3f}")
    print(f"  Firma radice (RSA-PSS)      : {_time_op(lambda: rsa_sign(priv, msg)):8.3f}")
    print(f"  Verifica firma (RSA-PSS)    : {_time_op(lambda: rsa_verify(pub, sig, msg)):8.3f}")
    print(f"  HMAC-SHA256 (calcolo tag)   : {_time_op(lambda: hmac_sha256(k, msg)):8.3f}")
    print(f"  HMAC-SHA256 (verifica tag)  : {_time_op(lambda: hmac_verify(k, msg, tag)):8.3f}")
    print(f"  Impronta SHA-256 chiave     : {_time_op(lambda: sha256_hex(k)):8.3f}")
    print(f"  Generazione nonce           : {_time_op(lambda: generate_nonce()):8.3f}")
    # Costo delle operazioni Shamir, suddivisione e ricostruzione del segreto.
    secret = 123456789
    sh = shamir.split_secret(secret, 3, 5)
    print(f"  Shamir split (3,5)          : {_time_op(lambda: shamir.split_secret(secret, 3, 5)):8.3f}")
    print(f"  Shamir recover (3 quote)    : {_time_op(lambda: shamir.recover_secret(sh[:3])):8.3f}")


def message_size(): # misura la dimensione in byte della quadrupla di voto.
    print(" DIMENSIONE DEI MESSAGGI (quadrupla c, t, token, k_enc)")

    priv, pub = generate_rsa_keypair()
    c = rsa_encrypt(pub, b"SI")                 # cifrato del voto: 256 byte (RSA-2048).
    k = generate_symmetric_key()
    k_enc = rsa_encrypt(pub, k)                 # chiave di integrita' incapsulata: 256 byte.
    nonce = generate_nonce()
    token = os.urandom(16).hex()
    tag = hmac_sha256(k, (c.hex() + "|" + token + "|" + nonce.hex()).encode())

    print(f"  c   (voto cifrato)          : {len(c):5d} byte")
    print(f"  t   (tag HMAC)              : {len(tag):5d} byte")
    print(f"  token (pseudonimo)          : {len(token)//2:5d} byte")
    print(f"  k_enc (chiave incapsulata)  : {len(k_enc):5d} byte")
    quad = len(c) + len(tag) + len(token)//2 + len(k_enc)
    print(f"  quadrupla totale (byte)     : {quad:5d} byte")


def scaling_benchmark(): # esegue un'elezione completa con numeri crescenti di elettori e misura la scalabilita'.
    print(" SCALABILITA': ELEZIONE COMPLETA AL CRESCERE DEGLI ELETTORI")
    print(f"  {'elettori':>9} | {'voto+reg (ms)':>14} | {'spoglio (ms)':>12} | "
          f"{'verifica univ. (ms)':>18}")

    for num in (10, 50, 100, 200): # setup di un'elezione 
        eligible = {f"e_{i:04d}" for i in range(num)}
        aa = RegistrationAuthority(eligible)
        bb = BulletinBoard()
        ae = ElectoralAuthority(bb, aa.public_key, aa.verify_token, t=3, n=5)
        commission = ScrutinyCommission(ae)
        shares = ae.distribute_shares()
         # fase di voto: ogni elettore ottiene il token, prepara la quadrupla e la invia.
        t0 = time.perf_counter()
        for i in range(num):
            v = Voter(f"e_{i:04d}")
            v.obtain_token(aa)
            nonce = ae.open_session()
            vote = "SI" if i % 2 == 0 else "NO"
            c, tag, token, k_enc = v.prepare_ballot(vote, ae.public_key, nonce)
            ae.collect_vote(c, tag, token, k_enc, nonce)
        t_vote = (time.perf_counter() - t0) * 1000.0
        # chiusura urne e scrutinio
        ae.close_and_publish()
        t0 = time.perf_counter()
        commission.tally(bb, presented_shares=shares[:3])
        t_tally = (time.perf_counter() - t0) * 1000.0
        # con la sola chiave pubblica dell'AE, viene controllata la validita' della firma sulla radice di Merkle.
        t0 = time.perf_counter() 
        bb.verify_published_root(ae.public_key)
        t_univ = (time.perf_counter() - t0) * 1000.0

        print(f"  {num:>9} | {t_vote:>14.2f} | {t_tally:>12.2f} | {t_univ:>18.2f}")


def main():

    print(" BENCHMARK DELLE PRESTAZIONI")

    micro_benchmarks()
    message_size()
    scaling_benchmark()


if __name__ == "__main__":
    main()
