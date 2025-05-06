import socket
import threading
import base64
from crypto_utils import generate_aes_key, encrypt_with_rsa, decrypt_with_aes, encrypt_with_aes

# Store clients' AES keys and IP addresses
clients = {}  # client_id: (addr, aes_key)
serverIP = "localhost"  # Server IP address
serverPort = 12345  # Server port
#Adding message types:
MSG_TYPE_KEY_EXCHANGE = b'\x01'  # \x is hexadecimal byte
MSG_TYPE_MESSAGE = b'\x02'  
MSG_TYPE_SERVER_RECONNECT_REQUEST=b'\x03'

def AES_key_request(sock,client_id,data, addr):
                        # First-time client
                        # 1. Decode and store the client's RSA public key: 
                        rsa_public_key = base64.b64decode(data)
                        # 2. Generate a random AES key
                        aes_key = generate_aes_key()
                        # 3. Encrypt the AES key with RSA public key
                        encrypted_key = encrypt_with_rsa(rsa_public_key, aes_key)
                        # 4. Send the encrypted AES key back (base64-encoded)
                        sock.sendto(MSG_TYPE_KEY_EXCHANGE+base64.b64encode(encrypted_key), addr)
                        # 5. Store AES key in `clients` for future communication
                        clients[client_id] = (addr,aes_key)
                        print(f"Client {client_id} ({addr}) connected. AES key sent.")

def handle_messages(sock):
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            #parsing message
            try:
                msg_type = data[:1]
                # username is 32 bytes long
                client_id = data[1:33].decode().strip()  # Extract client ID (36 bytes) and decode it. Stripping removes any trailing whitespace.
                data = data[33:]  # Remove the client ID and messageType from the data
            except Exception as e:
                print(f"Error parsing message from {addr}: {e}")
                continue

            print(f"Received data from {addr}")
            if client_id not in clients and msg_type == MSG_TYPE_KEY_EXCHANGE:
                try:
                    AES_key_request(sock,client_id,data, addr)
                except Exception as e:
                    print(f"Error handling new client {addr}: {e}")


            elif client_id in clients and msg_type == MSG_TYPE_MESSAGE:
                # Returning client
                # 1. Decrypt incoming message using this client's AES key
                addr, aes_key = clients[client_id]
                decrypted_message = decrypt_with_aes(aes_key, data)
                # 2. For each other client:
                #     a. Re-encrypt the message with their AES key
                #     b. Send the encrypted message to them
                for next_client_id, (next_client_addr,broadcastKey) in clients.items():
                    if next_client_id != client_id: #Don't send back to the sender
                        print(f"Sending message to {next_client_id}")
                        # Encrypt the message with the other client's AES key
                        encrypted_message = encrypt_with_aes(broadcastKey, decrypted_message)
                        # Send the encrypted message to the other client (base64-encoded)
                        try:
                            sock.sendto(MSG_TYPE_MESSAGE+client_id.ljust(36).encode()+encrypted_message.encode(), next_client_addr)
                        except Exception as e:
                            print(f"Error sending message to {next_client_id}: {e}")
            elif client_id in clients and msg_type == MSG_TYPE_KEY_EXCHANGE:
                # Client is trying to re-establish connection, need to get rid of old client key
                print(f"Client {client_id} ({addr}) re-establishing connection.")
                clients.pop(client_id, None) #remove the old client key if it exists
                AES_key_request(sock,client_id,data, addr) #call the function to handle the new client key exchange
            else:   #This means the client isnt following the protocol, so we should ignore them or ask them to send a new key
                print(f"Unknown message type from {addr}: {msg_type}")
                client_id="unsure"
                sock.sendto(MSG_TYPE_SERVER_RECONNECT_REQUEST, addr)
    except OSError as e:
        if e.errno == 10054:
            print(f"Socket closed. Error: {e}")

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
