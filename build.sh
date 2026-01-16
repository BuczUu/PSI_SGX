#!/bin/bash
# PSI_SGX Build Script - buduje enklawę i serwer RA-TLS

set -e  # Zatrzymaj przy błędach

echo "=== PSI_SGX Build Script ==="
echo ""

# Kolory
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Ustaw SGX_MODE na SIM jeśli nie ustawiono
export SGX_MODE=${SGX_MODE:-SIM}
export SGX_SDK=${SGX_SDK:-/opt/intel/sgxsdk}

echo -e "${YELLOW}SGX_MODE: $SGX_MODE${NC}"
echo -e "${YELLOW}SGX_SDK: $SGX_SDK${NC}"
echo ""

# Sprawdź czy SGX SDK jest zainstalowane
if [ ! -d "$SGX_SDK" ]; then
    echo -e "${RED}ERROR: SGX SDK not found at $SGX_SDK${NC}"
    echo "Please install SGX SDK or set SGX_SDK environment variable"
    exit 1
fi

# 1. Buduj enklawę
echo -e "${GREEN}[1/2] Building enclave...${NC}"
cd Enclave

# Generuj edge routines jeśli nie ma
if [ ! -f Enclave_t.c ] || [ ! -f Enclave_u.c ]; then
    echo "Generating edge routines from Enclave.edl..."
    $SGX_SDK/bin/x64/sgx_edger8r --trusted Enclave.edl --search-path $SGX_SDK/include --search-path $SGX_SDK/include/tlibc
    $SGX_SDK/bin/x64/sgx_edger8r --untrusted Enclave.edl --search-path $SGX_SDK/include --search-path $SGX_SDK/include/tlibc
fi

# Kompiluj enklawę
echo "Compiling enclave..."
g++ -c Enclave.cpp Enclave_t.c \
    -I. -I$SGX_SDK/include -I$SGX_SDK/include/tlibc -I$SGX_SDK/include/libcxx \
    -nostdinc -fPIC -fno-stack-protector -fvisibility=hidden \
    -std=c++11 -nostdinc++

# Linkuj enklawę
echo "Linking enclave..."
g++ Enclave.o Enclave_t.o -o ../enclave.so \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
    -L$SGX_SDK/lib64 \
    -Wl,--whole-archive -lsgx_trts$([[ "$SGX_MODE" == "SIM" ]] && echo "_sim") -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tkey_exchange -lsgx_tservice$([[ "$SGX_MODE" == "SIM" ]] && echo "_sim") -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 \
    -Wl,--version-script=Enclave.lds

# Podpisz enklawę
echo "Signing enclave..."
$SGX_SDK/bin/x64/sgx_sign sign \
    -key Enclave_private_test.pem \
    -enclave ../enclave.so \
    -out ../enclave.signed.so \
    -config Enclave.config.xml

cd ..
echo -e "${GREEN}✓ Enclave built successfully${NC}"
echo ""

# 2. Buduj serwer RA-TLS
echo -e "${GREEN}[2/2] Building server...${NC}"

# Kompiluj enclave_u.c jeśli trzeba
if [ ! -f Enclave/Enclave_u.o ]; then
    echo "Compiling Enclave_u.c..."
    g++ -c Enclave/Enclave_u.c -o Enclave/Enclave_u.o \
        -I. -IEnclave -I$SGX_SDK/include
fi

# Kompiluj ra_tls_fake.c
echo "Compiling RA-TLS fake..."
gcc -c ra_tls/ra_tls_fake.c -o ra_tls/ra_tls_fake.o \
    -Ira_tls -I$SGX_SDK/include

# Kompiluj i linkuj serwer
echo "Compiling server..."
URTS_LIB="sgx_urts"
if [ "$SGX_MODE" == "SIM" ]; then
    URTS_LIB="sgx_urts_sim"
fi

g++ -o server_ratls Server_RATLS.cpp Enclave/Enclave_u.o ra_tls/ra_tls_fake.o \
    -std=c++11 -Wall -Wextra \
    -I. -IEnclave -Ira_tls -I$SGX_SDK/include \
    -L$SGX_SDK/lib64 -l$URTS_LIB -lpthread \
    -lmbedtls -lmbedcrypto -lmbedx509

echo -e "${GREEN}✓ Server built successfully${NC}"
echo ""

# Podsumowanie
echo "=== Build Complete! ==="
echo ""
echo -e "${GREEN}Generated files:${NC}"
echo "  - enclave.signed.so (signed enclave)"
echo "  - server_ratls (RA-TLS server)"
echo ""
echo -e "${YELLOW}To run:${NC}"
echo "  ./run.sh"
echo ""
echo -e "${YELLOW}To test manually:${NC}"
echo "  Terminal 1: ./server_ratls"
echo "  Terminal 2: ./client_python.py 1"
echo "  Terminal 3: ./client_python.py 2"
echo ""
