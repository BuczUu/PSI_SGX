# PSI_SGX - Bezpieczne PSI z Remote Attestation

## Opis

To jest implementacja Private Set Intersection (PSI) używając Intel SGX z **jednokierunkowym Remote Attestation przez RA-TLS**.

### Architektura

```
┌─────────────────┐                     ┌──────────────────┐
│  Klient         │   TLS + SGX Quote   │   Serwer (SGX)   │
│  (Python)       │────────────────────►│   w enklawie     │
│  BEZ enklawy    │  Weryfikuje enkławę │   RA-TLS         │
└─────────────────┘                     └──────────────────┘
         │                                       │
         │     Zaszyfrowane żądanie PSI          │
         │──────────────────────────────────────►│
         │                                       │
         │                            ┌──────────▼────────┐
         │                            │  Enklawa          │
         │                            │  Obliczenia PSI   │
         │                            └──────────┬────────┘
         │                                       │
         │      Zaszyfrowany wynik PSI           │
         │◄──────────────────────────────────────│
         │                                       │
```

### Jak to działa?

1. **Klient BEZ SGX** - zwykły program w Pythonie, nie potrzebuje SGX
2. **Serwer z enklawą** - enklawy SGX oblicza PSI w bezpieczny sposób
3. **RA-TLS** - Remote Attestation wbudowane w TLS:
   - Serwer generuje certyfikat z SGX quote
   - Klient weryfikuje, że serwer działa w prawdziwej enklawie
   - Nawiązane zostaje bezpieczne połączenie TLS
4. **End-to-End szyfrowanie**:
   - ECDH wymiana kluczy (P-256)
   - AES-128-GCM szyfrowanie danych
   - Wszystko w enklawie - klucze nigdy nie wychodzą

## Wymagania

### Serwer (maszyna z SGX):
- Intel SGX SDK zainstalowany
- Linux
- `libmbedtls-dev`
- Gramine (opcjonalnie, dla prawdziwego RA-TLS)

### Klient (dowolna maszyna):
- Python 3.x
- `pip install cryptography`

## Budowanie

```bash
# Ustaw ścieżkę do SGX SDK jeśli trzeba
export SGX_SDK=/opt/intel/sgxsdk  # lub /home/marcel/sgx_lab/sgxsdk

# Tryb symulacji (bez prawdziwego SGX)
export SGX_MODE=SIM

# Zbuduj wszystko
./build.sh
```

## Uruchamianie

### Automatyczne demo (2 klientów):
```bash
./run.sh
```

### Ręcznie:

**Terminal 1 - Serwer:**
```bash
export LD_LIBRARY_PATH=$SGX_SDK/lib64:$LD_LIBRARY_PATH
./server_ratls
```

**Terminal 2 - Klient 1:**
```bash
python3 client_python.py 1
```

**Terminal 3 - Klient 2:**
```bash
python3 client_python.py 2
```

## Przykład

Klient 1 ma zbiór: `[1, 2, 3, 4, 5]`
Klient 2 ma zbiór: `[3, 4, 5, 6, 7]`

PSI (część wspólna): `[3, 4, 5]`

Oba klienty otrzymają ten sam wynik `[3, 4, 5]`, obliczony bezpiecznie w enklawie.

## Tryby

### SIM Mode (domyślnie)
```bash
export SGX_MODE=SIM
./build.sh
```
- Działa bez prawdziwego SGX
- Do testowania
- Quote nie jest prawdziwy
- Klient akceptuje symulowany quote (ustaw `ALLOW_SIM_MODE=True` w kliencie)

### HW Mode (produkcja)
```bash
export SGX_MODE=HW
./build.sh
```
- Wymaga prawdziwego SGX
- Quote jest prawdziwy
- Klient powinien weryfikować quote (ustaw `ALLOW_SIM_MODE=False`)

## Pliki

- `Server_RATLS.cpp` - Serwer z RA-TLS
- `client_python.py` - Klient Python (bez SGX)
- `Enclave/Enclave.cpp` - Kod enklawy (PSI + kryptografia)
- `Enclave/Enclave.edl` - Interfejs enklawy
- `ra_tls/ra_tls_fake.c` - Fake RA-TLS dla SIM mode
- `build.sh` - Skrypt budowania
- `run.sh` - Skrypt uruchamiania demo

## Bezpieczeństwo

✅ **Co jest bezpieczne:**
- Obliczenia PSI w enklawie
- End-to-end szyfrowanie ECDH + AES-GCM
- Klucze generowane i używane tylko w enklawie
- Remote attestation weryfikuje prawdziwość enklawy

⚠️ **Uwaga w SIM mode:**
- Quote jest symulowany, nie jest prawdziwy
- Tylko do testowania!
- W produkcji używaj HW mode i weryfikuj quote

## Troubleshooting

**Błąd: SGX SDK not found**
```bash
export SGX_SDK=/ścieżka/do/sgxsdk
```

**Błąd: libmbedtls not found**
```bash
sudo apt install libmbedtls-dev
```

**Błąd: Python cryptography not found**
```bash
pip3 install cryptography
```

**Serwer nie startuje**
```bash
# Sprawdź log
tail -f server.log

# Sprawdź czy SGX SDK działa
ls $SGX_SDK/lib64/
```

**Klient nie może się połączyć**
- Sprawdź czy serwer działa
- Sprawdź czy port 12345 jest wolny
- Sprawdź czy firewall nie blokuje

## Licencja

Ten kod jest do celów edukacyjnych i demonstracyjnych.
