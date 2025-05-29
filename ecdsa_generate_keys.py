

# Script: ecdsa_generate_keys.py
# Rol: Generează o singură dată cheile ECDSA și le salvează în fișiere PEM (cu parolă)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from getpass import getpass

# 1. Generare cheie privată ECDSA pe curba SECP256R1 (standard)
ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())

# 2. Obținere cheie publică
ecdsa_public_key = ecdsa_private_key.public_key()

# 3. Citirea parolei de la utilizator
parola = getpass("Introdu parola pentru criptarea cheii private ECDSA: ").encode()

# 4. Salvare cheie privată criptată în fișier PEM
with open("ecdsa_cheie_privata.pem", "wb") as f:
    f.write(ecdsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(parola)
    ))

# 5. Salvare cheie publică în fișier PEM
with open("ecdsa_cheie_publica.pem", "wb") as f:
    f.write(ecdsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Cheile ECDSA au fost generate și salvate cu succes (cheia privată este criptată).")