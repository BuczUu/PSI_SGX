#!/bin/bash
# Uruchom RA-TLS server w Docker Gramine

echo "=== Starting RA-TLS Server in Docker ==="

# Zatrzymaj stary kontener jeśli istnieje
sudo docker rm -f psi_sgx_server 2>/dev/null || true

# Uruchom kontener w tle z nazwą
sudo docker run -d --name psi_sgx_server \
  -p 12345:12345 \
  -v /home/marcel/sgx_lab:/home/marcel/sgx_lab:ro \
  gramineproject/gramine \
  bash -c "
    set -e
    cp -r /home/marcel/sgx_lab/examples/PSI_SGX /tmp/PSI_SGX
    cd /tmp/PSI_SGX
    apt-get update -qq
    apt-get install -y -qq build-essential pkg-config libmbedtls-dev
    export SGX_SDK=/home/marcel/sgx_lab/sgxsdk
    echo 'Building RA-TLS server...'
    make -f Makefile.ratls clean
    make -f Makefile.ratls
    echo ''
    echo '=== Server starting on port 12345 ==='
    gramine-direct ./server_ratls
  "

echo ""
echo "Server starting in background..."
echo "Waiting 10 seconds for build and startup..."
sleep 10

echo ""
echo "=== Server logs ==="
sudo docker logs psi_sgx_server

echo ""
echo "=== Server is running! ==="
echo "Test with: python3 client_python.py 1"
echo ""
echo "Stop server: sudo docker stop psi_sgx_server"
echo "View logs: sudo docker logs -f psi_sgx_server"
