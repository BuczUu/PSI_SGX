#!/bin/bash
# PSI_SGX Run Script - uruchamia serwer i dwóch klientów

set -e

echo "=== PSI_SGX Demo Runner ==="
echo ""

# Kolory
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Sprawdź czy serwer istnieje
if [ ! -f server_ratls ]; then
    echo -e "${RED}ERROR: server_ratls not found${NC}"
    echo "Please build first: ./build.sh"
    exit 1
fi

# Sprawdź czy enklawa istnieje
if [ ! -f enclave.signed.so ]; then
    echo -e "${RED}ERROR: enclave.signed.so not found${NC}"
    echo "Please build first: ./build.sh"
    exit 1
fi

# Sprawdź czy klient istnieje
if [ ! -f client_python.py ]; then
    echo -e "${RED}ERROR: client_python.py not found${NC}"
    exit 1
fi

chmod +x client_python.py

# Funkcja do czyszczenia procesów
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

# Uruchom serwer w tle
echo -e "${GREEN}Starting server...${NC}"
export LD_LIBRARY_PATH=$SGX_SDK/lib64:$LD_LIBRARY_PATH
./server_ratls > server.log 2>&1 &
SERVER_PID=$!

echo -e "${BLUE}Server PID: $SERVER_PID${NC}"
echo "Server log: tail -f server.log"
echo ""

# Poczekaj aż serwer się uruchomi
echo "Waiting for server to start..."
sleep 2

# Sprawdź czy serwer działa
if ! ps -p $SERVER_PID > /dev/null; then
    echo -e "${RED}ERROR: Server failed to start${NC}"
    echo "Check server.log for details"
    cat server.log
    exit 1
fi

echo -e "${GREEN}✓ Server started${NC}"
echo ""

# Uruchom klienta 1
echo -e "${GREEN}[Client 1] Starting...${NC}"
echo "Set: [1, 2, 3, 4, 5]"
python3 client_python.py 1 > client1.log 2>&1 &
CLIENT1_PID=$!

# Daj chwilę na połączenie
sleep 1

# Uruchom klienta 2
echo -e "${GREEN}[Client 2] Starting...${NC}"
echo "Set: [3, 4, 5, 6, 7]"
python3 client_python.py 2 > client2.log 2>&1 &
CLIENT2_PID=$!

echo ""
echo "Waiting for clients to finish..."

# Czekaj na klientów
wait $CLIENT1_PID
CLIENT1_EXIT=$?

wait $CLIENT2_PID
CLIENT2_EXIT=$?

echo ""
echo "=== Results ==="
echo ""

echo -e "${BLUE}[Client 1 Output]${NC}"
cat client1.log
echo ""

echo -e "${BLUE}[Client 2 Output]${NC}"
cat client2.log
echo ""

if [ $CLIENT1_EXIT -eq 0 ] && [ $CLIENT2_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ All clients completed successfully${NC}"
else
    echo -e "${RED}✗ Some clients failed${NC}"
    echo "Client 1 exit code: $CLIENT1_EXIT"
    echo "Client 2 exit code: $CLIENT2_EXIT"
fi

# Zatrzymaj serwer
echo ""
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo -e "${GREEN}Done!${NC}"
