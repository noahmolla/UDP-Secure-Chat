import socket
import threading
import base64
import sys, select #only works for windows from what I tested, for making the chat look nice
from crypto_utils import decrypt_with_aes, encrypt_with_aes, generate_rsa_keypair,decrypt_with_rsa

serverIP = "localhost"  # Server IP address
serverPort = 12345  # Server port
aes_key = None  # Will store AES key after exchange


#Adding message types:
MSG_TYPE_KEY_EXCHANGE = b'\x01'  # \x is hexadecimal byte
MSG_TYPE_MESSAGE = b'\x02'  
MSG_TYPE_SERVER_RECONNECT_REQUEST=b'\x03'

def send_server_RSA_pubkey():
    # Generate RSA keypair (2048-bit)
    # 1. Send base64-encoded public key to server
    #mark as key exchange message type
    concatanated_message = MSG_TYPE_KEY_EXCHANGE+username.ljust(36).encode()+base64.b64encode(public_key)
    sock.sendto(concatanated_message, server_addr)
    print("Public key sent to server. Waiting for AES key...")

def receive_messages(sock, private_key):
    global aes_key
    while True:
        data, _ = sock.recvfrom(4096) #_ because we don't need the address of the sender
        msg_type = data[0:1] #first byte is the message type
        data = data[1:] #remove the first byte from the data
        
        if aes_key is None and msg_type==MSG_TYPE_KEY_EXCHANGE:
            # First message: encrypted AES key from server
            # 1. Decode base64
            b64_encrypted_key = base64.b64decode(data)
            # 2. Decrypt with RSA private key, store AES key
            aes_key = decrypt_with_rsa(private_key, b64_encrypted_key)
            print("AES key received and decrypted.")
        elif aes_key and msg_type==MSG_TYPE_KEY_EXCHANGE:
            #For when server wants a new key
            b64_encrypted_key = base64.b64decode(data)
            # 2. Decrypt with RSA private key, store AES key
            aes_key = decrypt_with_rsa(private_key, b64_encrypted_key)
            print("AES key received and decrypted.")
        elif msg_type==MSG_TYPE_MESSAGE:
            from_username = data[0:32].decode().strip() # Extract username (32 bytes) and decode it. Stripping removes any trailing whitespace.
            data = data[32:]  # Remove the client ID and messageType from the data
            # Decrypt AES-encrypted message
            # 1. Decode base64
            b64_encrypted_message = data.decode()
            # 2. Decrypt using AES key
            decrypted_message = decrypt_with_aes(aes_key, b64_encrypted_message)
            # 3. Display message
            print(f"{from_username}: {decrypted_message}")
            pass
        elif msg_type==MSG_TYPE_SERVER_RECONNECT_REQUEST:
            print("Server requested a new key...")
            send_server_RSA_pubkey()
        else:
            print("Unknown message type or AES key not set.")

def main():
    global aes_key #global variable lets us modify aes_key in the receive_messages function
    global sock
    global server_addr
    global username
    global private_key
    global public_key
    private_key, public_key = generate_rsa_keypair()
    #pick username
    username = input("Enter your username: ")
    while len(username) > 32 or len(username) < 4:
        print("Please enter a username between 4 and 32 characters.")
        username = input("Enter your username: ")
    #ideally add username taken and input validation here
    #pad username with spaces to 36 characters
    username = username.ljust(36)
    # Setup UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (serverIP, serverPort)
    send_server_RSA_pubkey()
    # Start thread to receive messages
    threading.Thread(target=receive_messages, args=(sock, private_key), daemon=True).start() #daemon=True means the thread will exit when the main program exits

    # Chat loop: take input, encrypt with AES, send to server
    while True:
        #clear the input buffer so the flush doesn't get sent in certain cases
        #while select.select([sys.stdin], [], [], 0)[0]:
        #    sys.stdin.readline()

        msg = input("")   # Get user input
        if aes_key:
            # 1. Encrypt with AES
            encrypted_message = encrypt_with_aes(aes_key, msg)
            #  Send to server, mark as regular message type
            concatanated_message = MSG_TYPE_MESSAGE+username.encode()+encrypted_message.encode()
            sock.sendto(concatanated_message, server_addr)
            # Move cursor up one line and clear it to look nice, looked this up
            sys.stdout.write('\x1b[1A')      # Move up
            sys.stdout.write('\x1b[2K')      # Clear line
            sys.stdout.flush()
            print(f"Me: {msg}")

        
if __name__ == "__main__":
    main()
