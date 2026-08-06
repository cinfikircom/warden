# Bilerek açıklı fixture — yalnızca test amaçlı. Üretimde KULLANMA.
from Crypto.Cipher import AES


def encrypt(key, data):
    # B3-static-iv-py: sabit IV.
    cipher = AES.new(key, AES.MODE_CBC, b"0000000000000000")
    return cipher.encrypt(data)
