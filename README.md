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
- Encrypted chat message broadcasting.
- Real-time display of incoming messages.
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
  ```
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
  - The public key is base64-encoded and sent to the server.
  - The server generates a unique 128-bit AES key for the client and encrypts it with RSA.
  - The encrypted AES key is sent back to the client and decrypted using the private RSA key.

- **Message Encryption**:
  - Messages are encrypted using AES in CBC mode with a fresh random 16-byte IV for each message.
  - AES-encrypted messages are base64-encoded before being sent over UDP.
  - The server decrypts messages and re-encrypts them with each recipient's AES key before forwarding.

---

## Assumptions and Limitations

- Clients and server are assumed to run on localhost (127.0.0.1) for testing.
- No message authentication (HMAC) is implemented — this is only required for graduate-level students.
- Packet loss is not handled explicitly (as expected in UDP); no retransmissions or acknowledgments.
- No usernames or UI are implemented — messages are displayed as raw text.
- **Limitation**: If a client disconnects and reconnects while the server still has their IP/port cached, the server will treat them as an existing client and skip key exchange. This will cause communication to fail since the AES key will not match. Restarting the server resolves this. One way to fix this issue permanently would be to create and track session IDs. The user could send their session id in their first message, or every message, and the server could look for it. If the address is already in the dictionary but the current sessionID doesn't match their old sessionID, then assume this message has their RSA public key and send them an AES key.

---

## Author

Noah Molla 
Undergraduate
San Diego State University — COMPE 560  
Due Date: May 5, 2025

---