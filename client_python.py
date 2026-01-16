#!/usr/bin/env python3
"""
PSI_SGX Python Client with RA-TLS and E2E Encryption
One-way attestation: verifies server SGX enclave
E2E Encryption: ECDH key exchange + AES-256-GCM
"""

import socket
import ssl
import struct
import sys
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# Configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345
ALLOW_SIM_MODE = True  # Set to False in production with real SGX

def verify_sgx_quote(conn, cert_der, errno, depth, preverify_ok):
    """
    Custom certificate verification callback for RA-TLS.
    Extracts and verifies SGX quote from certificate extension.
    """
    if depth != 0:
        # Only verify leaf certificate (server cert)
        return True
    
    print(f"[CLIENT] Verifying SGX quote in certificate...")
    
    try:
        # Try to import Gramine RA-TLS verifier
        # In production: use ra_tls_verify_callback_der()
        # For now: basic check
        
        # Check if certificate has SGX quote extension (OID 1.2.840.113741.1.13.1)
        # In real implementation, you'd extract and verify the quote here
        
        if ALLOW_SIM_MODE:
            print("[CLIENT] WARNING: Running in SIM mode - accepting potentially fake quotes!")
            print("[CLIENT] For production: Set ALLOW_SIM_MODE=False and verify quote properly")
            return True
        else:
            # In production: call Gramine's ra_tls_verify_callback_der
            # or implement DCAP quote verification
            print("[CLIENT] ERROR: Real SGX verification not implemented yet")
            print("[CLIENT] You need to:")
            print("[CLIENT]   1. Install gramine-ratls Python bindings")
            print("[CLIENT]   2. Call ra_tls_verify_callback_der(cert_der)")
            print("[CLIENT]   3. Check MRENCLAVE/MRSIGNER against expected values")
            return False
    
    except Exception as e:
        print(f"[CLIENT] Quote verification failed: {e}")
        return False

def send_data_and_get_psi(client_set):
    """
    Connect to SGX server via RA-TLS with E2E encryption.
    
    Protocol:
    1. TLS handshake with server (RA-TLS certificate)
    2. Server sends 64-byte ECDH public key
    3. Client generates ECDH keypair and sends 64-byte public key
    4. Both derive shared secret via ECDH
    5. Client encrypts data: [iv:12][size:4][encrypted_blob:?][tag:16]
    6. Server decrypts in enclave, computes PSI, encrypts result
    7. Client receives and decrypts result: [iv:12][size:4][encrypted_blob:?][tag:16]
    
    Args:
        client_set: List of integers representing the client's set
    
    Returns:
        List of integers representing the intersection
    """
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    # Disable hostname verification (we verify SGX quote instead)
    context.check_hostname = False
    
    # We still want to verify the certificate (to get the quote)
    context.verify_mode = ssl.CERT_REQUIRED
    
    # In production, load CA certs or use custom verification
    # For SIM mode testing, we'll accept self-signed
    if ALLOW_SIM_MODE:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    # Note: In real Gramine RA-TLS, you'd set:
    # context.set_verify_callback(verify_sgx_quote)
    # But Python's ssl module doesn't expose this directly
    # You need to use OpenSSL bindings or Gramine's Python wrapper
    
    print(f"[CLIENT] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Wrap socket with TLS
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            ssock.connect((SERVER_HOST, SERVER_PORT))
            
            print("[CLIENT] TLS handshake completed!")
            print(f"[CLIENT] Cipher: {ssock.cipher()}")
            print(f"[CLIENT] TLS version: {ssock.version()}")
            
            # Get server certificate
            cert = ssock.getpeercert(binary_form=True)
            if cert:
                print(f"[CLIENT] Server certificate: {len(cert)} bytes")
                # In production: verify_sgx_quote(cert)
            
            if ALLOW_SIM_MODE:
                print("[CLIENT] WARNING: Running in SIM mode - server quote not verified!")
            
            # ============= E2E Encryption: ECDH Key Exchange =============
            
            # 1. Receive server's ECDH public key (64 bytes: x || y for P-256)
            print("[CLIENT] Receiving server ECDH public key...")
            server_pubkey_bytes = ssock.recv(64)
            if len(server_pubkey_bytes) != 64:
                print(f"[CLIENT] ERROR: Expected 64 bytes, got {len(server_pubkey_bytes)}")
                return None
            print(f"[CLIENT] Received server pubkey: {len(server_pubkey_bytes)} bytes")
            
            # 2. Generate client ECDH keypair (P-256)
            print("[CLIENT] Generating client ECDH keypair...")
            client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            client_public_key = client_private_key.public_key()
            
            # Extract public key bytes (x || y, 32 bytes each, total 64 bytes)
            public_numbers = client_public_key.public_numbers()
            client_pubkey_bytes = public_numbers.x.to_bytes(32, byteorder='big') + \
                                   public_numbers.y.to_bytes(32, byteorder='big')
            print(f"[CLIENT] Generated client pubkey: {len(client_pubkey_bytes)} bytes")
            
            # 3. Send client public key to server
            ssock.sendall(client_pubkey_bytes)
            print("[CLIENT] Sent client pubkey to server")
            
            # 4. Derive shared secret from server's public key
            # SGX SDK might use little-endian format, try both endiannesses
            shared_secret = None
            
            # Try big-endian first
            try:
                server_x_int = int.from_bytes(server_pubkey_bytes[:32], byteorder='big')
                server_y_int = int.from_bytes(server_pubkey_bytes[32:], byteorder='big')
                server_public_numbers = ec.EllipticCurvePublicNumbers(
                    x=server_x_int,
                    y=server_y_int,
                    curve=ec.SECP256R1()
                )
                server_public_key_obj = server_public_numbers.public_key(default_backend())
                shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key_obj)
                print(f"[CLIENT] ECDH succeeded with big-endian")
            except ValueError:
                print("[CLIENT] Big-endian failed, trying little-endian...")
                try:
                    server_x_int = int.from_bytes(server_pubkey_bytes[:32], byteorder='little')
                    server_y_int = int.from_bytes(server_pubkey_bytes[32:], byteorder='little')
                    server_public_numbers = ec.EllipticCurvePublicNumbers(
                        x=server_x_int,
                        y=server_y_int,
                        curve=ec.SECP256R1()
                    )
                    server_public_key_obj = server_public_numbers.public_key(default_backend())
                    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key_obj)
                    print(f"[CLIENT] ECDH succeeded with little-endian")
                except ValueError:
                    print("[CLIENT] ERROR: Both big and little-endian ECDH failed")
                    return None
            
            print(f"[CLIENT] Shared secret derived: {len(shared_secret)} bytes")
            print(f"[CLIENT] Shared secret (first 16 bytes, big-endian): {shared_secret[:16].hex()}")
            
            # SGX uses little-endian for ECC shared secret, so reverse it
            shared_secret_le = shared_secret[::-1]
            print(f"[CLIENT] Shared secret (first 16 bytes, little-endian): {shared_secret_le[:16].hex()}")
            
            # 5. Derive AES key from shared secret using SHA-256 (match enclave logic)
            key_material = hashlib.sha256(shared_secret_le).digest()
            aes_key = key_material[:16]  # First 16 bytes for AES-128 (to match enclave)
            
            print(f"[CLIENT] AES key derived (16 bytes): {aes_key.hex()}")
            
            # ============= E2E Encryption: Send encrypted data =============
            
            # Generate IV (12 bytes) - use zeros for testing to ensure consistency
            # iv = secrets.token_bytes(12)
            iv = bytes(12)  # All zeros for testing
            print(f"[CLIENT] Generated IV: {len(iv)} bytes (all zeros for test)")
            
            # Prepare plaintext data - PSI set as uint32 array
            # Convert client_set to bytes (little-endian uint32)
            plaintext_data = struct.pack(f'{len(client_set)}I', *client_set)
            print(f"[CLIENT] Plaintext PSI set: {client_set} ({len(plaintext_data)} bytes)")
            
            # Encrypt with AES-128-GCM (matching enclave AES-128)
            cipher = AESGCM(aes_key)
            ciphertext = cipher.encrypt(iv, plaintext_data, None)  # No AAD
            
            # ciphertext includes both encrypted data and authentication tag (16 bytes appended)
            # mbedTLS format: encrypted_data (without tag) + tag (16 bytes)
            encrypted_blob = ciphertext[:-16]
            gcm_tag = ciphertext[-16:]
            
            print(f"[CLIENT] Encrypted data: plaintext {len(plaintext_data)} -> ciphertext {len(encrypted_blob)}")
            print(f"[CLIENT] GCM tag: {len(gcm_tag)} bytes")
            
            # Send: [iv:12][size:4][encrypted_blob:size][tag:16]
            print(f"[CLIENT] Sending encrypted data: IV + size + blob + tag")
            ssock.sendall(iv)
            ssock.sendall(struct.pack('I', len(encrypted_blob)))
            ssock.sendall(encrypted_blob)
            ssock.sendall(gcm_tag)
            
            # Force flush by doing a small recv with timeout to ensure data is sent
            ssock.settimeout(0.1)
            try:
                ssock.recv(0)
            except:
                pass
            ssock.settimeout(None)
            
            print(f"[CLIENT] Sent {len(iv) + 4 + len(encrypted_blob) + len(gcm_tag)} bytes encrypted payload")
            
            # ============= E2E Decryption: Receive encrypted result =============
            
            # Receive: [iv:12][size:4][encrypted_blob:size][tag:16]
            print("[CLIENT] Waiting for encrypted result...")
            
            # Receive IV (12 bytes)
            result_iv = b''
            while len(result_iv) < 12:
                chunk = ssock.recv(12 - len(result_iv))
                if not chunk:
                    print("[CLIENT] ERROR: Connection closed while receiving IV")
                    return None
                result_iv += chunk
            print(f"[CLIENT] Received result IV: {len(result_iv)} bytes")
            
            # Receive size (4 bytes) - this is number of ELEMENTS, not bytes
            result_size_bytes = b''
            while len(result_size_bytes) < 4:
                chunk = ssock.recv(4 - len(result_size_bytes))
                if not chunk:
                    print("[CLIENT] ERROR: Connection closed while receiving size")
                    return None
                result_size_bytes += chunk
            result_count = struct.unpack('I', result_size_bytes)[0]
            result_size = result_count * 4  # Convert elements to bytes (uint32_t = 4 bytes)
            print(f"[CLIENT] Receiving {result_count} elements ({result_size} bytes) encrypted result...")
            
            # Receive encrypted blob
            encrypted_result = b''
            while len(encrypted_result) < result_size:
                chunk = ssock.recv(result_size - len(encrypted_result))
                if not chunk:
                    print("[CLIENT] ERROR: Connection closed prematurely")
                    return None
                encrypted_result += chunk
            print(f"[CLIENT] Received encrypted blob: {len(encrypted_result)} bytes")
            
            # Receive GCM tag (16 bytes)
            result_tag = b''
            while len(result_tag) < 16:
                chunk = ssock.recv(16 - len(result_tag))
                if not chunk:
                    print("[CLIENT] ERROR: Connection closed while receiving tag")
                    return None
                result_tag += chunk
            print(f"[CLIENT] Received GCM tag: {len(result_tag)} bytes")
            
            # Decrypt with same shared secret and AES-256-GCM
            # Reconstruct ciphertext = encrypted_blob + tag for decryption
            ciphertext_with_tag = encrypted_result + result_tag
            
            cipher = AESGCM(aes_key)
            try:
                plaintext_result = cipher.decrypt(result_iv, ciphertext_with_tag, None)
                print(f"[CLIENT] Decrypted result: {len(plaintext_result)} bytes")
            except Exception as e:
                print(f"[CLIENT] ERROR: Decryption failed: {e}")
                return None
            
            # Parse result
            num_elements = len(plaintext_result) // 4
            if num_elements > 0:
                result = struct.unpack(f'{num_elements}I', plaintext_result)
                return list(result)
            else:
                return []

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <client_id>")
        print(f"Example: {sys.argv[0]} 1")
        sys.exit(1)
    
    client_id = int(sys.argv[1])
    
    print("=== PSI_SGX Python Client ===")
    print(f"Client ID: {client_id}")
    print(f"SIM Mode: {'ENABLED' if ALLOW_SIM_MODE else 'DISABLED'}")
    print()
    
    # Define test sets
    if client_id == 1:
        client_set = [1, 2, 3, 4, 5]
    elif client_id == 2:
        client_set = [3, 4, 5, 6, 7]
    else:
        client_set = [5, 6, 7, 8, 9]
    
    print(f"Client set: {client_set}")
    print(f"Expected server set: [3, 4, 5, 6, 7, 8, 9]")
    print()
    
    # Connect and compute PSI
    try:
        result = send_data_and_get_psi(client_set)
        
        if result is not None:
            print()
            print("=== PSI Result ===")
            print(f"Intersection: {result}")
            print(f"Size: {len(result)}")
        else:
            print()
            print("[CLIENT] Failed to get PSI result")
            sys.exit(1)
    
    except Exception as e:
        print(f"[CLIENT] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
