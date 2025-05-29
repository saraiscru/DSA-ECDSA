


# Script: dsa_sign_verify.py
# Rol: Functii pentru semnare si verificare DSA folosind chei din fisiere PEM
from cryptography.hazmat.primitives import serialization
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
import time
# Funcție care semnează un mesaj folosind cheia privată DSA
def semneaza_mesaj_dsa(mesaj: bytes) -> bytes:
    with open("dsa_cheie_privata.pem", "rb") as f:
        parola = getpass("Introdu parola pentru decriptarea cheii private DSA: ").encode()
        private_key = serialization.load_pem_private_key(f.read(), password=parola)
    return private_key.sign(mesaj, hashes.SHA256())

# Funcție care verifică dacă semnătura este validă pentru un mesaj dat
def verifica_semnatura_dsa(mesaj: bytes, semnatura: bytes) -> bool:
    with open("dsa_cheie_publica.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    try:
        public_key.verify(semnatura, mesaj, hashes.SHA256())
        return True
    except Exception:
        return False
# Funcție care afișează componentele r și s ale unei semnături DSA și dimensiunea ei
def detalii_semnatura_dsa(semnatura: bytes):
    r, s = utils.decode_dss_signature(semnatura)
    print(f"Semnatura are componentele:\nr = {r}\ns = {s}")
    print("Dimensiune semnatura (bytes):", len(semnatura))
    
# Funcție care măsoară timpul de semnare și verificare pentru DSA
def masoara_timpi_dsa(mesaj: bytes):
    with open("dsa_cheie_privata.pem", "rb") as f:
        parola = getpass("Introdu parola pentru decriptarea cheii private DSA: ").encode()
        private_key = serialization.load_pem_private_key(f.read(), password=parola)
    with open("dsa_cheie_publica.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    start = time.perf_counter()
    semnatura = private_key.sign(mesaj, hashes.SHA256())
    end = time.perf_counter()
    print("Timp semnare:", end - start, "secunde")

    start = time.perf_counter()
    public_key.verify(semnatura, mesaj, hashes.SHA256())
    end = time.perf_counter()
    print("Timp verificare:", end - start, "secunde")
    
# Funcție care testează semnătura pe un mesaj modificat (pentru a verifica integritatea)
def test_pe_mesaj_modificat_dsa(semnatura: bytes):
    mesaj_modificat = b"Mesaj alterat"
    with open("dsa_cheie_publica.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    try:
        public_key.verify(semnatura, mesaj_modificat, hashes.SHA256())
        print("Semnatura este valida pe mesaj modificat (NU E BINE)")
    except:
        print("Semnatura esueaza pe mesaj modificat – corect")

