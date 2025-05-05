from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def generate_rsa_keypair():
    # Generate a 2048-bit RSA key pair
    # Return: (private_key_bytes, public_key_bytes)
    key = RSA.generate(2048)
    private_key = key.export_key() #(format='PEM')export the private key in PEM format, trying to fix the error
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_rsa(public_key_bytes, message_bytes):
    # Encrypt a message (AES key) using the client's RSA public key
    pub_key = RSA.import_key(public_key_bytes) #convert bytes to RSA key object
    cipher_rsa = PKCS1_OAEP.new(pub_key) #create a new RSA cipher object using OAEP padding
    encrypted_bytes = cipher_rsa.encrypt(message_bytes) #encrypt the message using the RSA cipher object
    return encrypted_bytes #return the encrypted message as bytes

def decrypt_with_rsa(private_key_bytes, encrypted_bytes):
    # Decrypt an AES key using your private RSA key
    priv_key = RSA.import_key(private_key_bytes) #convert bytes to RSA key object
    cipher_rsa = PKCS1_OAEP.new(priv_key) #create a new RSA cipher object using OAEP padding
    return cipher_rsa.decrypt(encrypted_bytes) #decrypt the message using the RSA cipher object and return the result as bytes

# AES ENCRYPTION FUNCTIONS

def generate_aes_key():
    return get_random_bytes(16) # Generate a random 128-bit AES key (16 bytes)

def encrypt_with_aes(aes_key, plaintext):
    #Generate random IV (initialization vector) for AES encryption
    iv = get_random_bytes(16) # AES block size is 16 bytes
    # Pad the plaintext to be a multiple of the block size. 
    # Plaintext must be encoded because we are passing raw string
    padded_plaintext = pad(plaintext.encode(), AES.block_size) 
    cipher = AES.new(aes_key, AES.MODE_CBC, iv) # Create a new AES cipher object in CBC mode with the given key and IV. 
    #CBC mode prevents repeated blocks of plaintext from producing the same ciphertext.
    ciphertext = cipher.encrypt(padded_plaintext) # Encrypt the padded plaintext using the AES cipher object
    return base64.b64encode(iv + ciphertext).decode() #encoding the concatted text then base64 encoding then decoding to a string for transmission

    

def decrypt_with_aes(aes_key, b64_ciphertext):
    # Decrypt AES-encrypted message (base64-encoded string)
    # 1. Base64-decode input to get IV + ciphertext
    raw = base64.b64decode(b64_ciphertext) #decode the base64 encoded string to bytes
    # 2. Separate IV from ciphertext
    iv = raw[:16] #first 16 bytes are the IV
    # 3. Decrypt and unpad to get plaintext
    ciphertext = raw[16:] #the rest is the ciphertext
    cipher = AES.new(aes_key, AES.MODE_CBC, iv) # Create a new AES cipher object in CBC mode with the given key and IV.
    padded_plaintext = cipher.decrypt(ciphertext) # Decrypt the ciphertext using the AES cipher object
    # 4. Unpad the plaintext to remove padding
    plaintext = unpad(padded_plaintext, AES.block_size) #remove the padding from the plaintext
    # 5. Return the plaintext as a string
    return plaintext.decode() #decode the bytes to a string and return it
    
