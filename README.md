# README for "Security Analysis of TLS/SSL Handshake and Application Data Protocol"

## Project Overview
This project, conducted as part of **ECE 628 – Computer Security** at the University of Waterloo. It implements RSA & Ephemeral DHE handshakes between Client & Server from scratch for TLS/SSL protocol (TLS 1.2).

It also investigates the security protocols of **Transport Layer Security (TLS)** and **Secure Sockets Layer (SSL)**, focusing on handshake processes and application data protocols. The goal is to assess vulnerabilities, evaluate security mechanisms, and explore improvements in TLS/SSL to ensure secure communication over the internet.

## Key Objectives:
- Analyze the **TLS/SSL handshake** protocols, including **Diffie-Hellman (DHE)** and **RSA**.
- Understand the application data protocol to secure transmitted data.
- Evaluate vulnerabilities in key exchange and authentication processes.
  
## Implementation Details
1. **DHE Handshake:**
   - The client initiates a secure session by sending a `client_hello` to the server. 
   - The server responds with a `server_hello`, containing necessary cryptographic parameters like prime modulus, generator, and its Diffie-Hellman public key.
   - Both the client and server generate public-private key pairs for secure key exchange.
  
2. **RSA Handshake:**
   - The client sends a `client_hello`, and the server responds with its public key and digital certificate.
   - The client encrypts a pre-master secret using the server's public key, and both parties derive a master secret.
  
3. **Testing & Output:**
   - Logs and terminal outputs capture the handshake details for both **DHE** and **RSA**, verifying correct key generation and shared secret computation.

## Conclusion:
The TLS/SSL protocol is critical for secure online communication. While DHE ensures **forward secrecy**, it introduces computational overhead. RSA, on the other hand, offers **faster key exchange** but lacks forward secrecy. Ensuring **continuous updates** to cryptographic standards and user education is vital for robust security.

## Key Features:
- Evaluation of DHE and RSA handshakes.
- Security analysis of key exchange and data encryption.
- Identification of potential attacks and vulnerabilities.

## Technologies Used:
- **C++** for handshake protocol simulation.
- **CryptoPP library** for cryptographic operations.
- **Wireshark** for packet capture and analysis.

## Author:
**Kabiir Krishna**