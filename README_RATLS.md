# PSI_SGX with Gramine RA-TLS

This is a complete implementation of Private Set Intersection (PSI) using Intel SGX with **one-way Remote Attestation via RA-TLS**.

## Architecture

```
┌─────────────────┐                     ┌──────────────────┐
│  Client         │   TLS + SGX Quote   │   Server (SGX)   │
│  (Python/Go)    │────────────────────►│   Gramine        │
│  No enclave     │  Verify attestation │   RA-TLS         │
└─────────────────┘                     └──────────────────┘
         │                                       │
         │         Encrypted PSI request         │
         │──────────────────────────────────────►│
         │                                       │
         │                            ┌──────────▼────────┐
         │                            │  Enclave          │
         │                            │  PSI Computation  │
         │                            └──────────┬────────┘
         │                                       │
         │         Encrypted PSI result          │
         │◄──────────────────────────────────────│
         │                                       │
```

## Features

- ✅ **One-way attestation**: Only server has SGX enclave, clients verify server
- ✅ **Multi-language clients**: Python, Go (Java, Rust, etc. easy to add)
- ✅ **RA-TLS**: Remote Attestation built into TLS handshake
- ✅ **SIM mode support**: Test without real SGX hardware
- ✅ **DCAP-based**: Modern Linux SGX attestation
- ✅ **Encrypted computation**: PSI computed inside enclave

## Requirements

### Server (SGX machine)
```bash
# Install Gramine
curl -fsSL https://packages.gramineproject.io/gramine-keyring.gpg | sudo apt-key add -
echo 'deb [arch=amd64] https://packages.gramineproject.io/ focal main' | sudo tee /etc/apt/sources.list.d/gramine.list
sudo apt update
sudo apt install gramine gramine-ratls-dcap

# Install SGX SDK
# Follow: https://github.com/intel/linux-sgx

# Install dependencies
sudo apt install build-essential libmbedtls-dev
```

### Clients (any machine)
```bash
# Python 3.x (built-in ssl module)
python3 --version

# Go 1.16+ (built-in crypto/tls)
go version
```

## Build

### Build Server
```bash
cd /home/marcel/sgx_lab/examples/PSI_SGX

# Build enclave first (if not already built)
cd Enclave
make
cd ..

# Build RA-TLS server
make -f Makefile.ratls
```

This creates:
- `server_ratls` - RA-TLS server binary
- `server_ratls.manifest.sgx` - Gramine manifest
- `enclave.signed.so` - Signed enclave
- `client_go` - Go client binary

### Build Clients
```bash
# Python - no build needed
chmod +x client_python.py

# Go
make -f Makefile.ratls client_go
```

## Run

### Terminal 1: Start Server

**SIM mode** (no SGX hardware):
```bash
gramine-direct ./server_ratls
```

**SGX mode** (with SGX hardware):
```bash
gramine-sgx ./server_ratls
```

Expected output:
```
=== PSI_SGX RA-TLS Server ===
Attestation: One-way (clients verify server)
TLS Library: mbedTLS with Gramine RA-TLS

[SERVER] Enclave created successfully (EID: 2)
[SERVER] Generating RA-TLS certificate with SGX quote...
[SERVER] RA-TLS certificate generated (4532 bytes)
[SERVER] RA-TLS key generated (1234 bytes)
[SERVER] Listening on port 12345...
```

### Terminal 2: Run Python Client

```bash
python3 client_python.py 1
```

Expected output:
```
=== PSI_SGX Python Client ===
Client ID: 1
SIM Mode: ENABLED

Client set: [1, 2, 3, 4, 5]
Expected server set: [3, 4, 5, 6, 7, 8, 9]

[CLIENT] Connecting to 127.0.0.1:12345...
[CLIENT] TLS handshake completed!
[CLIENT] WARNING: Running in SIM mode - server quote not verified!
[CLIENT] Sending set: [1, 2, 3, 4, 5]
[CLIENT] Sent 20 bytes
[CLIENT] Receiving 12 bytes result...

=== PSI Result ===
Intersection: [3, 4, 5]
Size: 3
```

### Terminal 3: Run Go Client

```bash
./client_go 2
```

Expected output:
```
=== PSI_SGX Go Client ===
Client ID: 2
SIM Mode: ENABLED

Client set: [3 4 5 6 7]
Expected server set: [3, 4, 5, 6, 7, 8, 9]

[CLIENT] Connecting to 127.0.0.1:12345...
[CLIENT] TLS handshake completed!
[CLIENT] WARNING: Running in SIM mode - server quote not verified!
[CLIENT] Sending set: [3 4 5 6 7]
[CLIENT] Sent 20 bytes
[CLIENT] Receiving 28 bytes result...

=== PSI Result ===
Intersection: [3 4 5 6 7]
Size: 5
```

## Configuration

### SIM Mode vs Production

**Python client** (`client_python.py`):
```python
ALLOW_SIM_MODE = True   # For testing without SGX
ALLOW_SIM_MODE = False  # Production - verify real quotes
```

**Go client** (`client_go.go`):
```go
const AllowSimMode = true   // For testing without SGX
const AllowSimMode = false  // Production - verify real quotes
```

### Server Set

Edit `Server_RATLS.cpp`, line ~150:
```cpp
uint32_t server_set[] = {3, 4, 5, 6, 7, 8, 9};
```

## Security Notes

### SIM Mode
⚠️ **SIM mode provides NO security**:
- Quotes are fake (all zeros or dummy data)
- No integrity verification
- No confidentiality guarantees
- **Only for testing/development**

### Production Mode
For real security with SGX hardware:

1. **Server**: Run with `gramine-sgx` (not `gramine-direct`)
2. **Clients**: Set `ALLOW_SIM_MODE = False`
3. **Verify quotes**: Implement proper DCAP verification:
   ```python
   # Python - use Gramine bindings
   from gramine_ratls import verify_quote_callback
   
   # Verify MRENCLAVE against expected value
   expected_mrenclave = bytes.fromhex("your_enclave_measurement")
   verify_quote_callback(cert_der, expected_mrenclave)
   ```

4. **PCCS setup**: Configure Provisioning Certificate Caching Service
5. **Pin MRENCLAVE**: Always check server's MRENCLAVE matches expected value

## Adding More Client Languages

### Java
```java
import javax.net.ssl.*;
// Use SSLSocket with custom TrustManager
// Verify SGX quote in checkServerTrusted()
```

### Rust
```rust
use rustls::ClientConfig;
// Use custom ServerCertVerifier
// Verify SGX quote in verify_server_cert()
```

### Node.js
```javascript
const tls = require('tls');
// Use checkServerIdentity option
// Verify SGX quote in callback
```

All clients use standard TLS libraries + custom quote verification!

## Troubleshooting

### "Failed to create enclave"
- Check `enclave.signed.so` exists in same directory as server
- Verify SGX driver loaded: `ls /dev/sgx*`
- Check Gramine installed: `gramine-sgx --version`

### "ra_tls_create_key_and_crt_der failed"
- Install `gramine-ratls-dcap`: `sudo apt install gramine-ratls-dcap`
- Check RA-TLS library: `ldconfig -p | grep ra_tls`

### "Connection refused"
- Check server is running on port 12345
- Check firewall: `sudo ufw allow 12345`

### "TLS handshake failed"
- Check mbedTLS installed: `dpkg -l | grep mbedtls`
- Check Gramine manifest permissions

## Original Code

The original mutual attestation code is preserved in:
- `Server.cpp` - Original server with mutual RA
- `Client.cpp` - Original client with enclave

This RA-TLS version is cleaner and supports multi-language clients!

## References

- [Gramine RA-TLS Documentation](https://gramine.readthedocs.io/en/latest/attestation.html)
- [Intel SGX DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives)
- [RA-TLS Paper](https://arxiv.org/abs/1801.05863)
