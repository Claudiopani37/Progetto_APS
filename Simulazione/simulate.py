from pki import CertificationAuthority
from authorities_registration import RegistrationAuthority, VotingToken
from authorities_electoral import ElectoralAuthority, ScrutinyCommission
from bulletin_board import BulletinBoard, VoteRecord
from voter import Voter
from crypto_primitives import rsa_encrypt, hmac_sha256, sha256_hex, generate_symmetric_key


def main():
    print(" SIMULAZIONE REFERENDUM BINARIO Si'/No — WP4")

    print("\n[1] SETUP e PKI")
    ca = CertificationAuthority()                      # l'Universita' come CA

    eligible = {f"elettore_{i:02d}" for i in range(1, 8)}   # 7 aventi diritto
    aa = RegistrationAuthority(eligible_voters=eligible)
    bb = BulletinBoard()
    ae = ElectoralAuthority(bb, aa.public_key, aa.verify_token, t=3, n=5)
    commission = ScrutinyCommission(ae)

    cert_aa = ca.issue_certificate("AA", aa.public_key)
    cert_ae = ca.issue_certificate("AE", ae.public_key)
    print(f"    Certificato AA valido         : {ca.verify_certificate(cert_aa)}")
    print(f"    Certificato AE valido         : {ca.verify_certificate(cert_ae)}")

    shares = ae.distribute_shares()                    # quote ai commissari
    print(f"    Quote Shamir distribuite      : {len(shares)} (soglia t=3)")
    print(f"    Chiave privata AE protetta da Shamir: si'")

    print("\n[2] AUTENTICAZIONE e VOTAZIONE (nonce, quadrupla, 4 controlli)")
    intended = {
        "elettore_01": "SI", "elettore_02": "NO", "elettore_03": "SI",
        "elettore_04": "SI", "elettore_05": "NO", "elettore_06": "SI",
    }   # elettore_07 si astiene

    voters = {}
    for idx, (vid, vote) in enumerate(intended.items()):
        v = Voter(vid)
        v.obtain_token(aa)                             # genera k_mac + impronta -> AA
        nonce = ae.open_session()                      # challenge-response
        c, tag, token, k_enc = v.prepare_ballot(vote, ae.public_key, nonce)
        accepted = ae.collect_vote(c, tag, token, k_enc, nonce)
        voters[vid] = v

        # Dettaglio completo della cifratura per OGNI elettore.
        print(f"DETTAGLIO CIFRATURA ({vid}, voto in chiaro = '{vote}') ---")
        print(f"k_mac (chiave HMAC, 256 bit) : {v._k_mac.hex()[:48]}...")
        print(f"impronta k_mac (SHA-256): {token.key_fpr[:48]}...")
        print(f"pseudonimo (token): {token.pseudonym}")
        print(f"firma AA sul token (RSA-PSS): {token.signature.hex()[:48]}... ({len(token.signature)} byte)")
        print(f"nonce di sessione: {nonce.hex()}")
        print(f"c = RSA-OAEP(PK_AE, voto) : {c[:48]}... ({len(bytes.fromhex(c))} byte)")
        print(f"k_enc = RSA-OAEP(PK_AE,k_mac): {k_enc.hex()[:48]}... ({len(k_enc)} byte)")
        print(f"tag = HMAC_k_mac(c|token|n): {tag[:48]}... ({len(bytes.fromhex(tag))} byte)")
        print(f"Registrato sul BB: {accepted}")

    print(f"Voti registrati sul BB: {len(bb.records)}")

    print("\n[3] CHIUSURA URNE")
    ae.close_and_publish()
    print(f"Radice di Merkle pubblicata: {bb.merkle_root[:32]}...")
    print(f"Verifica universale (root): {bb.verify_published_root(ae.public_key)}")
    print(f"Contenuto pubblico del BB")
    for i, r in enumerate(bb.records):
        print(f"foglia {i}: pseudonimo={r.token[:12]}...  c(cifrato)={r.c[:24]}...")

    print("\n[4] VERIFICA INDIVIDUALE (ogni elettore controlla la propria foglia)")
    all_ok = all(v.verify_individual(bb) for v in voters.values())
    print(f"Tutte le verifiche individuali OK: {all_ok}")

    print("\n[5] SCRUTINIO (Commissione ricostruisce la chiave privata AE via Shamir)")
    result = commission.tally(bb, presented_shares=shares[:3])
    print(f"Quote presentate: 3/5 (soglia raggiunta)")
    print(f"Risultato: {result}")
    expected_si = sum(1 for x in intended.values() if x == "SI")
    expected_no = sum(1 for x in intended.values() if x == "NO")
    print(f"Atteso: Si': {expected_si} | No: {expected_no}")
    print(f"Conteggio corretto: {result.si == expected_si and result.no == expected_no}")

    # Prova concreta della randomizzazione: stesso voto -> due cifrati diversi.
    print("\nProva: stesso voto 'SI' cifrato due volte produce c diversi")
    c1 = rsa_encrypt(ae.public_key, b"SI").hex()
    c2 = rsa_encrypt(ae.public_key, b"SI").hex()
    print(f"c (1a cifratura): {c1[:40]}...")
    print(f"c (2a cifratura): {c2[:40]}...")
    print(f"c1 == c2 ? {c1 == c2}  (atteso False: cifrati indistinguibili)")

    print(" SCENARI DI ATTACCO (le proprieta' di sicurezza devono respingerli)")

    # A) Non-avente-diritto
    print("\n[A] Autenticita': un non-avente-diritto tenta di registrarsi")
    intruso = Voter("intruso_99")
    try:
        intruso.obtain_token(aa)
        print("FALLIMENTO DI SICUREZZA: token rilasciato")
    except PermissionError as e:
        print(f"Respinto dall'AA: {e}")

    # B) Doppia registrazione (unicita' lato AA)
    print("\n[B] Unicita': un elettore tenta un secondo token")
    try:
        voters["elettore_01"].obtain_token(aa)
        print("FALLIMENTO DI SICUREZZA: secondo token rilasciato")
    except PermissionError as e:
        print(f"Respinto dall'AA: {e}")

    # C) Token contraffatto (firma AA non valida)
    print("\n[C] Autenticita': voto con token non firmato dall'AA")
    fake_token = VotingToken(pseudonym="f" * 32, key_fpr=sha256_hex(b"x"), signature=b"\x00" * 256)
    vx = Voter("elettore_07"); vx.token = fake_token; vx._k_mac = b"x" * 32
    nonce = ae.open_session()
    c = rsa_encrypt(ae.public_key, b"SI").hex()
    k_enc = rsa_encrypt(ae.public_key, b"x" * 32)
    tag = hmac_sha256(b"x" * 32, (c + "|" + fake_token.pseudonym + "|" + nonce.hex()).encode()).hex()
    accepted = ae.collect_vote(c, tag, fake_token, k_enc, nonce)
    print(f"Voto accettato dall'AE: {accepted}  (atteso False)")

    # D) Manomissione in transito (HMAC)
    print("\n[D] Integrita' transito: un attivo altera c dopo l'HMAC")
    vg = Voter("elettore_07"); vg.obtain_token(aa)
    nonce = ae.open_session()
    c, tag, token, k_enc = vg.prepare_ballot("NO", ae.public_key, nonce)
    tampered = bytearray(bytes.fromhex(c)); tampered[5] ^= 0xFF
    accepted = ae.collect_vote(tampered.hex(), tag, token, k_enc, nonce)
    print(f"Voto manomesso accettato: {accepted}  (atteso False)")

    # E) Doppio uso dello stesso token (unicita' lato AE)
    print("\n[E] Unicita': riuso di un token gia' consumato")
    v2 = voters["elettore_02"]
    nonce = ae.open_session()
    c, tag, token, k_enc = v2.prepare_ballot("SI", ae.public_key, nonce)
    accepted = ae.collect_vote(c, tag, token, k_enc, nonce)
    print(f"Secondo voto accettato: {accepted}  (atteso False)")

    # F) Riuso del token INTERCETTATO con chiave diversa (controllo impronta SHA-256)
    print("\n[F] Furto token: avversario riusa il token di un onesto con propria chiave")
    k_adv = generate_symmetric_key()
    nonce = ae.open_session()
    c_adv = rsa_encrypt(ae.public_key, b"SI").hex()
    k_enc_adv = rsa_encrypt(ae.public_key, k_adv)
    tag_adv = hmac_sha256(k_adv, (c_adv + "|" + vg.token.pseudonym + "|" + nonce.hex()).encode()).hex()
    accepted = ae.collect_vote(c_adv, tag_adv, vg.token, k_enc_adv, nonce)
    print(f"    Voto con token altrui + chiave propria accettato: {accepted}  (atteso False)")

    # G) Replay con nonce non emesso dall'AE
    print("\n[G] Replay: invio di un messaggio con nonce non valido")
    fake_nonce = b"\x11" * 16   # nonce mai emesso da open_session()
    c, tag, token, k_enc = vg.prepare_ballot("NO", ae.public_key, fake_nonce)
    accepted = ae.collect_vote(c, tag, token, k_enc, fake_nonce)
    print(f"Voto con nonce non emesso accettato: {accepted}  (atteso False)")

    # H) Alterazione del registro dopo la pubblicazione (tamper-evidence)
    print("\n[H] Integrita' registro: alterazione di una foglia gia' pubblicata")
    original = bb.records[0]
    bb.records[0] = VoteRecord(c=original.c, tag=original.tag, token="TOKEN_FALSIFICATO")
    still_valid = bb.verify_published_root(ae.public_key)
    print(f"Verifica universale dopo alterazione: {still_valid}  (atteso False)")
    bb.records[0] = original

    # I) Spoglio con quote Shamir insufficienti
    print("\n[I] Riservatezza: spoglio con sole 2 quote su soglia 3")
    try:
        commission.tally(bb, presented_shares=shares[:2])
        print("FALLIMENTO DI SICUREZZA: spoglio eseguito")
    except PermissionError as e:
        print(f"Respinto dalla Commissione: {e}")

    print(" FINE SIMULAZIONE")

if __name__ == "__main__":
    main()