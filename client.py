import socket
import threading
import base64
from crypto_utils import decrypt_with_aes, encrypt_with_aes, generate_rsa_keypair,decrypt_with_rsa

serverIP = "localhost"  # Server IP address
serverPort = 12345  # Server port
aes_key = None  # Will store AES key after exchange

def receive_messages(sock, private_key):
    global aes_key
    while True:
        data, _ = sock.recvfrom(4096) #_ because we don't need the address of the sender

        if aes_key is None:
            # First message: encrypted AES key from server
            # 1. Decode base64
            b64_encrypted_key = base64.b64decode(data)
            # 2. Decrypt with RSA private key, store AES key
            aes_key = decrypt_with_rsa(private_key, b64_encrypted_key)
        else:
            # Decrypt AES-encrypted message
            # 1. Decode base64
            b64_encrypted_message = data.decode()
            # 2. Decrypt using AES key
            decrypted_message = decrypt_with_aes(aes_key, b64_encrypted_message)
            # 3. Display message
            print(f"Msg: {decrypted_message}")
            pass

def main():
    global aes_key #global variable lets us modify aes_key in the receive_messages function

    # Setup UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (serverIP, serverPort)

    # Generate RSA keypair (2048-bit)
    # 1. Send base64-encoded public key to server
    private_key, public_key = generate_rsa_keypair()
    sock.sendto(base64.b64encode(public_key), server_addr)

    # Start thread to receive messages
    threading.Thread(target=receive_messages, args=(sock, private_key), daemon=True).start() #daemon=True means the thread will exit when the main program exits

    # Chat loop: take input, encrypt with AES, send to server
    while True:
        msg = input()   # Get user input
        if aes_key:
            # 1. Encrypt with AES
            encrypted_message = encrypt_with_aes(aes_key, msg)
            #  Send to server
            sock.sendto(encrypted_message.encode(), server_addr)
        else:
            print("Waiting for key exchange...")

if __name__ == "__main__":
    main()
