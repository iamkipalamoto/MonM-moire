from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib
BLOCK_SIZE = 32

#------------------------------------------------------------- A
# Clé privée et publique pour l'objet A
private_key_A = ec.derive_private_key(int.from_bytes(hashlib.sha256(b'test1').digest(), byteorder='big'), curve=ec.SECP256R1(), backend=default_backend())
public_key_A = private_key_A.public_key()

# Simuler l'envoi de la clé publique à l'objet B
public_key_A_bytes = public_key_A.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

public_key_A_bytes_hex = public_key_A_bytes.hex()
print("Clé publique Capteur : ", public_key_A_bytes_hex)
print("\n\n")
#------------------------------------------------------------- B
# Simuler la réception de la clé publique de l'objet A (remplacer ceci dans la vraie communication)
received_public_key_A_bytes = bytes.fromhex(public_key_A_bytes_hex)

# Charger la clé publique de l'objet A
public_key_A_received = serialization.load_der_public_key(received_public_key_A_bytes, backend=default_backend())

# Clé privée et publique pour l'objet B
private_key_B = ec.derive_private_key(int.from_bytes(hashlib.sha256(b'test2').digest(), byteorder='big'), curve=ec.SECP256R1(), backend=default_backend())
public_key_B = private_key_B.public_key()

public_key_B_bytes = public_key_B.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
public_key_B_bytes_hex = public_key_B_bytes.hex()
print("Clé publique Server:", public_key_B_bytes_hex )
print("\n\n")


#--------------------------------------------------------- A



# Simuler la réception de la clé publique de l'objet B (remplacer ceci dans la vraie communication)
received_public_key_B_bytes = bytes.fromhex(public_key_B_bytes_hex)

# Charger la clé publique de l'objet B
public_key_B_received = serialization.load_der_public_key(received_public_key_B_bytes, backend=default_backend())

# Effectuer l'échange de clés Diffie-Hellman
shared_key_A = private_key_A.exchange(ec.ECDH(), public_key_B)
shared_key_A_hex = shared_key_A.hex()
# Simuler l'envoi de la clé partagée à l'objet B
print("Clé partagée Capteur :", shared_key_A_hex)
print("\n\n")

# Chiffrer le message "bonjour" avec la clé partagée
cipher = AES.new(shared_key_A, AES.MODE_ECB)
print("Entrer le message à Chiffrer")
message = input()
ciphertext = cipher.encrypt(pad(message.encode("utf-8"),BLOCK_SIZE))

# Simuler l'envoi du message chiffré à l'objet B
print("Message par le Capteur :", ciphertext.hex())
print("\n\n")

#-------------------------------------------------------------- B

# Effectuer l'échange de clés Diffie-Hellman
shared_key = private_key_B.exchange(ec.ECDH(), public_key_A_received)
print("Clé partagée Server:", shared_key)
print("\n\n")

# Simuler le déchiffrement du message avec la clé partagée
cipher = AES.new(shared_key, AES.MODE_ECB)
decrypted_message = cipher.decrypt(ciphertext)

# Afficher le message déchiffré
print("Message déchiffré par le Server :", decrypted_message.decode('utf-8'))
print("\n\n")
