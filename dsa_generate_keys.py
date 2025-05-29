# Script: dsa_generate_keys.py
# Rol: Generează o singură dată cheile DSA și le salvează în fișiere PEM (cu parolă)


from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from getpass import getpass

# 1. Generare cheie privata DSA (2048 biti)
dsa_private_key = dsa.generate_private_key(key_size=2048)

# 2. Obtinere cheie publica
dsa_public_key = dsa_private_key.public_key()

# 3. Citirea parolei de la utilizator (nu va fi afisata in terminal)
parola = getpass("Introdu parola pentru criptarea cheii private: ").encode()

# 4. Salvare cheie privata criptata in fisier PEM
with open("dsa_cheie_privata.pem", "wb") as f:
    f.write(dsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(parola)
    ))

# 5. Salvare cheie publica in fisier PEM
with open("dsa_cheie_publica.pem", "wb") as f:
    f.write(dsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Cheile DSA au fost generate si salvate cu succes (cheia privata este criptata).")
