
# Script: ecdsa_sign_verify.py
# Rol: Funcții pentru semnare și verificare ECDSA folosind chei din fișiere PEM

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from getpass import getpass
import time

def semneaza_mesaj_ecdsa(mesaj: bytes) -> bytes:
    with open("ecdsa_cheie_privata.pem", "rb") as f:
        parola = getpass("Introdu parola pentru decriptarea cheii private ECDSA: ").encode()
        private_key = serialization.load_pem_private_key(f.read(), password=parola)
    return private_key.sign(mesaj, ec.ECDSA(hashes.SHA256()))

def verifica_semnatura_ecdsa(mesaj: bytes, semnatura: bytes) -> bool:
    with open("ecdsa_cheie_publica.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    try:
        public_key.verify(semnatura, mesaj, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def detalii_semnatura_ecdsa(semnatura: bytes):
    r, s = utils.decode_dss_signature(semnatura)
    print(f"Semnatura ECDSA are componentele:\nr = {r}\ns = {s}")
    print("Dimensiune semnatura (bytes):", len(semnatura))

def masoara_timpi_ecdsa(mesaj: bytes):
    with open("ecdsa_cheie_privata.pem", "rb") as f:
        parola = getpass("Introdu parola pentru decriptarea cheii private ECDSA: ").encode()
        private_key = serialization.load_pem_private_key(f.read(), password=parola)
    with open("ecdsa_cheie_publica.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    start = time.perf_counter()
    semnatura = private_key.sign(mesaj, ec.ECDSA(hashes.SHA256()))
    end = time.perf_counter()
    print("Timp semnare ECDSA:", end - start, "secunde")

    start = time.perf_counter()
    public_key.verify(semnatura, mesaj, ec.ECDSA(hashes.SHA256()))
    end = time.perf_counter()
    print("Timp verificare ECDSA:", end - start, "secunde")

def test_pe_mesaj_modificat_ecdsa(semnatura: bytes):
    mesaj_modificat = b"Mesaj alterat"
    with open("ecdsa_cheie_publica.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    try:
        public_key.verify(semnatura, mesaj_modificat, ec.ECDSA(hashes.SHA256()))
        print("Semnatura ECDSA este valida pe mesaj modificat (NU E BINE)")
    except:
        print("Semnatura ECDSA esueaza pe mesaj modificat – corect")