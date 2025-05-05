import socket
import threading
import base64
from crypto_utils import generate_aes_key, encrypt_with_rsa, decrypt_with_aes, encrypt_with_aes

# Store clients' AES keys and IP addresses
clients = {}  # addr: aes_key
client_keys = {}  # addr: rsa_public_key
serverIP = "localhost"  # Server IP address
serverPort = 12345  # Server port
def handle_messages(sock):
    try:
        while True:
            data, addr = sock.recvfrom(4096)

            if addr not in clients:
                try:
                    # First-time client
                    # 1. Decode and store the client's RSA public key: 
                    rsa_public_key = base64.b64decode(data)
                    # 2. Generate a random AES key
                    aes_key = generate_aes_key()
                    # 3. Encrypt the AES key with RSA public key
                    encrypted_key = encrypt_with_rsa(rsa_public_key, aes_key)
                    # 4. Send the encrypted AES key back (base64-encoded)
                    sock.sendto(base64.b64encode(encrypted_key), addr)
                    # 5. Store AES key in `clients` for future communication
                    clients[addr] = aes_key
                    # 6. Store the client's RSA public key for future communication
                    client_keys[addr] = rsa_public_key
                except Exception as e:
                    print(f"Error handling new client {addr}: {e}")


            else:
                # Returning client
                # 1. Decrypt incoming message using this client's AES key
                aes_key = clients[addr]
                decrypted_message = decrypt_with_aes(aes_key, data)
                # 2. For each other client:
                #     a. Re-encrypt the message with their AES key
                #     b. Send the encrypted message to them
                for client_addr, client_aes_key in clients.items():
                    if client_addr != addr: #Don't send back to the sender
                        # Encrypt the message with the other client's AES key
                        encrypted_message = encrypt_with_aes(client_aes_key, decrypted_message)
                        # Send the encrypted message to the other client (base64-encoded)
                        sock.sendto(encrypted_message.encode(), client_addr)
    except Exception as e:
        print(f"Error handling messages: {e}")

def main():
    # Setup UDP socket and bind to port 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((serverIP, serverPort))
    print(f"Server started on port {serverPort}")
    # Start handling messages
    try:
        threading.Thread(target=handle_messages, args=(sock,), daemon=True).start() #daemon=True means the thread will exit when the main program exits
        while True:
            # Keep the main thread alive
            pass
    except KeyboardInterrupt:   #SO i can stop the server with Ctrl+C, need threading bc its blocking 
        print("Server shutting down...")
        sock.close()

if __name__ == "__main__":
    main()
