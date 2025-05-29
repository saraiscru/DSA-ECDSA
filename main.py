

print("\n===== SEMNATURA DSA =====\n")
from dsa_sign_verify import (
    semneaza_mesaj_dsa,
    verifica_semnatura_dsa,
    detalii_semnatura_dsa,
    masoara_timpi_dsa,
    test_pe_mesaj_modificat_dsa
)

mesaj = b"Mesaj test pentru licenta"

# Semnare
semnatura = semneaza_mesaj_dsa(mesaj)
print("Semnatura DSA a fost generata")

# Verificare
if verifica_semnatura_dsa(mesaj, semnatura):
    print("Semnatura este valida")
else:
    print("Semnatura NU este valida")

# Detalii
detalii_semnatura_dsa(semnatura)

# Timpi de semnare/verificare
masoara_timpi_dsa(mesaj)

# Test mesaj modificat
test_pe_mesaj_modificat_dsa(semnatura)

print("\n===== SEMNATURA ECDSA =====\n")
#ECDSA


from ecdsa_sign_verify import (
    semneaza_mesaj_ecdsa,
    verifica_semnatura_ecdsa,
    detalii_semnatura_ecdsa,
    masoara_timpi_ecdsa,
    test_pe_mesaj_modificat_ecdsa
)

# Mesaj nou pentru semnare cu ECDSA
mesaj_ecdsa = b"Mesaj semnat cu ECDSA"

# Semnare
semnatura_ecdsa = semneaza_mesaj_ecdsa(mesaj_ecdsa)
print("Semnătura ECDSA a fost generată")

# Verificare
if verifica_semnatura_ecdsa(mesaj_ecdsa, semnatura_ecdsa):
    print("Semnătura ECDSA este validă")
else:
    print("Semnătura ECDSA NU este validă")

# Detalii despre semnătură
detalii_semnatura_ecdsa(semnatura_ecdsa)

# Timpi semnare/verificare
masoara_timpi_ecdsa(mesaj_ecdsa)

# Test semnătură pe mesaj modificat
test_pe_mesaj_modificat_ecdsa(semnatura_ecdsa)

print("\n===========================\n")

