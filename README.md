# COMPE 560 Secure UDP Chat Application

## Overview

This project implements a secure UDP-based chat system in Python using a hybrid cryptographic model:
- **RSA (2048-bit)** public-key cryptography for key exchange.
- **AES (128-bit, CBC mode)** symmetric encryption for message confidentiality.

The system allows multiple clients to exchange messages via a central server, with all communication securely encrypted over the inherently insecure UDP protocol.

---

## Features

- RSA public/private key generation on the client side.
- Per-client AES session key securely distributed by the server.
- AES-encrypted chat message broadcasting via server relay.
- **Message types using 1-byte headers**, enabling protocol extensibility:
  - `0x01`: RSA key exchange (client to server, server to client)
  - `0x02`: AES-encrypted message (client to server to clients)
  - `0x03`: Server reconnect request (server to client)
- **Username support** (up to 32 characters), used to identify chat participants.
- **Auto-reconnect if server crashes**: Clients will resend RSA public key automatically when prompted by the server.
- **Graceful client reconnection**: If a client closes and reopens the terminal with the same username, the server will re-issue a new AES key.
- Message formatting includes sender username and clean UI (previous line clearing).
- Base64 encoding to ensure safe UDP transmission.
- Graceful shutdown via `Ctrl+C`.

---

## Files Included

- `client.py` — UDP chat client
- `server.py` — UDP chat server
- `crypto_utils.py` — Cryptographic utility functions (RSA + AES)
- `README.md` — This documentation file

---

## How to Run

### Requirements

- Python 3.7+
- Install required library:
  ```bash
  pip install pycryptodome
  ```

### Start the Server

```bash
python server.py
```

### Start a Client (in a separate terminal)

```bash
python client.py
```

You can run multiple instances of `client.py` to simulate multiple users on the same machine.

---

## Cryptographic Design

- **Key Exchange**:
  - Each client generates a 2048-bit RSA key pair on startup.
  - The public key is base64-encoded and sent to the server with a message type header.
  - The server generates a unique 128-bit AES key per client and encrypts it with the client's RSA public key.
  - The client receives and decrypts the AES key using their private key.

- **Message Encryption**:
  - Messages are AES-encrypted in CBC mode with a random 16-byte IV per message.
  - The encrypted messages are base64-encoded and include the message type and sender's username.
  - The server decrypts the original message and re-encrypts it with each recipient’s AES key before forwarding.

---

## Assumptions and Limitations

- Clients and server are assumed to run on localhost (127.0.0.1) for testing.
- Packet loss is not handled explicitly (as expected in UDP); no retransmissions or acknowledgments.
- **Username-based session logic**: Reconnecting with the same username replaces the old session (AES key is reissued).
- **Known limitation**: On Localhost only: If a client disconnects and restarts with a *new* username, but from the *same IP+NEWport*, the server may be unable to correctly evict the old session. This may lead to socket errors or message drops. Only occurs because there are multiple clients on localhost.
---

## Author

Noah Molla  
Undergraduate  
San Diego State University — COMPE 560  
Due Date: May 5, 2025