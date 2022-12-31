import uuid, binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# Generata Key for A
keyA = RSA.generate(2048)
privateKeyA = keyA.export_key()
file_out = open("privateKeyA.pem", "wb")
file_out.write(privateKeyA)
file_out.close()

publicKeyA = keyA.publickey().export_key()
file_out = open("publicKeyA.pub", "wb")
file_out.write(publicKeyA)
file_out.close()

# Generate Key for B
keyB = RSA.generate(2048)
privateKeyB = keyB.export_key()
file_out = open("privateKeyB.pem", "wb")
file_out.write(privateKeyB)
file_out.close()

publicKeyB = keyB.publickey().export_key()
file_out = open("publicKeyB.pub", "wb")
file_out.write(publicKeyB)
file_out.close()

# -------------------------------------------------------------------------------
print("-----------------------------------------------------------------------")
# Step 1
# A initiate connection to B by sending Nonce 1 and its own ID
print("1. E(PUb, [N1 || IDa])")
print("A initiate connection to B by sending Nonce 1 and its own ID\n")

# Nonce 1
n1 = uuid.uuid4().bytes
print("Nonce 1=", binascii.hexlify(n1))

# Id A inistance
IdA = b"AInstance"
print("Id A=", IdA)

# Complete message to send from A to B
msg = n1 + IdA
print("Message to send from A to B=", binascii.hexlify(msg))

# Encrypted the message using B Public Key
keyUsed = RSA.import_key(open("publicKeyB.pub").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)
encryptedText = cipher_rsa.encrypt(msg)
print("Encrypted Message from A to B=", binascii.hexlify(encryptedText))

# B receives the message and decrypt it using its own Private Key
keyUsed = RSA.import_key(open("privateKeyB.pem").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)
decryptedText = cipher_rsa.decrypt(encryptedText)
print("Decrypted Message receives by B from A=", binascii.hexlify(decryptedText))
print("-----------------------------------------------------------------------\n")
# --------------------------------------------------------------------------------

# ---------------------------------------------------------------------------------
print("-----------------------------------------------------------------------")
# Step 2
# After receiving the initiation packet from A, B generate another Nonce and send it back
# alongside the Nonce1 that had been sent before
print("2. E(PUa, [N1 || N2])")
print("After receiving the initiation packet from A, B generate another Nonce and send it back alongside the Nonce1 that had been sent before")

# Nonce 2
n2 = uuid.uuid4().bytes
print("Nonce 2=", binascii.hexlify(n2))

# Complete message to send from n1 to n2
msg = n1 + n2
print("Message to send from B to A=", binascii.hexlify(msg))

# Encrypted the message using A Public Key
keyUsed = RSA.import_key(open("publicKeyA.pub").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)
encryptedText = cipher_rsa.encrypt(msg)
print("Encrypted Message from B to A=", binascii.hexlify(encryptedText))

# A receives the message and decrypt it using its own Private Key
keyUsed = RSA.import_key(open("privateKeyA.pem").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)
decryptedText = cipher_rsa.decrypt(encryptedText)
print("Decrypted Message receives by A from B=", binascii.hexlify(decryptedText))
print("-----------------------------------------------------------------------\n")
# --------------------------------------------------------------------------------

# -------------------------------------------------------------------------------
print("-----------------------------------------------------------------------")
# Step 3
# A receives the Nonce 2 from B, to reassure B instance before sending the key session,
# A sends back the N2 to B
print("3. E(PUb, N2)")
print("A receives the Nonce 2 from B, to reassure B instance before sending the key session, A sends back the N2 to B\n")

# Nonce 2
print("Nonce 2=", binascii.hexlify(n2))

msg = n2

# Encrypted the message using B Public Key
keyUsed = RSA.import_key(open("publicKeyB.pub").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)
encryptedText = cipher_rsa.encrypt(msg)
print("Encrypted Message from A to B=", binascii.hexlify(encryptedText))

# B receives the message and decrypt it using its own Private Key
keyUsed = RSA.import_key(open("privateKeyB.pem").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)
decryptedText = cipher_rsa.decrypt(encryptedText)
print("Decrypted Message receives by B from A=", binascii.hexlify(decryptedText))
print("-----------------------------------------------------------------------\n")
# --------------------------------------------------------------------------------

# -------------------------------------------------------------------------------
print("-----------------------------------------------------------------------")
# Step 4
# Last step after A reassure the B instance, A generate a secret key to sent to B by encrypting it with
# it's own Private Key to make sure that it was from A and then send it to B
print("4. E (PUb, E(PRa, Ks))")
print("# Last step after A reassure the B instance, A generate a secret key to sent to B by encrypting it with it's own Private Key to make sure that it was from A and then send it to B\n")

# Generate Secret Key
secretKey = uuid.uuid4().bytes
print("Session Key from A to B:", binascii.hexlify(secretKey))

# Encrypt the Secret Key with A private key
keyUsed = RSA.import_key(open("privateKeyA.pem").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)
encryptedSK = cipher_rsa.encrypt(secretKey)
print("Encrypted secretKey=", binascii.hexlify(encryptedSK))

# Encrypt the encrypted secret key using the Public Key B and sent it to B
keyUsed = RSA.import_key(open("publicKeyB.pub").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)

# Spliit the encryptedkey to a certain size to be encrypt, and then join it all together
splitSize = 128
tempChunks = [encryptedSK[i:i+splitSize] for i in range(0, len(encryptedSK), splitSize)]
encryptedSKChunks = []
for chunk in tempChunks:
    encryptedSKChunks.append(cipher_rsa.encrypt(chunk))
encryptedText = b''.join(encryptedSKChunks)
print("Encrypted Message sent from A to B:", binascii.hexlify(encryptedText))

# Decrypted secret key received by B from A using D (PUa, E(PRb, Encrypted Text)) to retrieve the Secret Key
splitSize = 256
tempChunks = [encryptedText[i:i+splitSize] for i in range(0, len(encryptedText), splitSize)]
decryptedChunks = []

# Get the encrypted secret key
keyUsed = RSA.import_key(open("privateKeyB.pem").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)
for chunk in tempChunks:
    decryptedChunks.append(cipher_rsa.decrypt(chunk))
decryptedText = b''.join(decryptedChunks)
print("Decrypted text received by B from A=", binascii.hexlify(decryptedText))

# Get the raw secret key from A
keyUsed = RSA.import_key(open("privateKeyA.pem").read())
cipher_rsa = PKCS1_OAEP.new(keyUsed)
secretKeyDecrypted = cipher_rsa.decrypt(decryptedText)
print("Secret key receives by B from A=", binascii.hexlify(secretKeyDecrypted))

print("-----------------------------------------------------------------------\n")
# --------------------------------------------------------------------------------