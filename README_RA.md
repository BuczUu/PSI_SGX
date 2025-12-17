# PSI_SGX - Private Set Intersection with Intel SGX and Remote Attestation

## Opis projektu

Serwer wykorzystujący Intel SGX do bezpiecznego obliczania części wspólnej (PSI) zbiorów danych od wielu klientów. System implementuje:

1. **Remote Attestation (RA)** - weryfikacja zgodności kodu serwera przez klientów
2. **Weryfikacja certyfikatów klientów** - pinned certificates w kodzie serwera
3. **Obliczenie PSI w enklawię** - dane chronione w zaufanym środowisku

## Architektura bezpieczeństwa

### Po stronie serwera:
- **Pinned Certificates** (`client_certs.h`): Lista autoryzowanych klientów z ich hashami certyfikatów
- **Weryfikacja klienta**: Przed przyjęciem danych, serwer sprawdza czy certyfikat klienta jest na liście
- **Remote Attestation**: Inicjalizacja kontekstu RA dla każdego klienta
- **PSI w enklawię**: Obliczenie części wspólnej odbywa się w chronionym środowisku

### Po stronie klienta:
- **Wysłanie certyfikatu**: Klient przedstawia swój certyfikat (hash)
- **Weryfikacja serwera**: Klient weryfikuje MRENCLAVE serwera (Remote Attestation)
- **Bezpieczne połączenie**: Po pomyślnej RA, dane są wymieniane

## Dlaczego certyfikaty są "zaszyte" w kodzie?

Pinning certyfikatów w kodzie serwera (`client_certs.h`) zapewnia:

1. **Kontrola dostępu**: Tylko znani klienci mogą uczestniczyć w protokole
2. **Ochrona przed atakiem MITM**: Nie można podmienić certyfikatu w trakcie działania
3. **Audit trail**: Lista autoryzowanych klientów jest jawna i stała
4. **Zero-trust architecture**: Serwer nie ufa żadnemu klientowi bez weryfikacji

W produkcyjnym środowisku:
- Każdy klient ma unikalne MRENCLAVE (pomiar kodu enklawiy)
- Certyfikaty są powiązane z kluczami publicznymi
- Lista może być aktualizowana tylko przez administratora z rebuild'em serwera

## Struktura projektu

```
PSI_SGX/
├── Enclave/
│   ├── Enclave.edl         # EDL z funkcjami RA (enclave_init_ra, verify_att_result_mac)
│   ├── Enclave.cpp         # Implementacja PSI + RA w enklawię
│   └── Enclave.config.xml  # Konfiguracja enklawiy
├── Server.cpp              # Serwer multi-client z RA i weryfikacją certów
├── Client.cpp              # Klient wysyłający certyfikat i weryfikujący serwer
├── client_certs.h          # Pinned certificates (MRENCLAVE + cert hashes)
└── Makefile                # Build z bibliotekami RA (sgx_tkey_exchange, sgx_ukey_exchange)
```

## Kompilacja

```bash
make SGX_MODE=SIM SGX_DEBUG=1
```

Komponenty:
- `server` - serwer multi-client z RA
- `client` - klient z weryfikacją RA

## Uruchomienie (3 terminale)

### Terminal 1 - Serwer:
```bash
./server
```

Serwer:
1. Inicjalizuje enklawę
2. Nasłuchuje na porcie 12345
3. Dla każdego klienta:
   - Weryfikuje certyfikat (pinned list)
   - Inicjalizuje RA context
   - Przyjmuje dane
4. Po otrzymaniu danych od obu klientów: oblicza PSI i wysyła wyniki

### Terminal 2 - Klient 1:
```bash
./client 1
```

Klient 1:
1. Łączy się z serwerem
2. Wysyła swój certyfikat (hash z `client_certs.h`)
3. Czeka na potwierdzenie autentykacji
4. Wysyła zbiór: {1, 2, 3, 4, 5}

### Terminal 3 - Klient 2:
```bash
./client 2
```

Klient 2:
1. Łączy się z serwerem
2. Wysyła swój certyfikat
3. Czeka na potwierdzenie
4. Wysyła zbiór: {3, 4, 5, 6, 7}
5. **Odbiera wynik PSI: {3, 4, 5}**

## Przykładowy output

### Serwer:
```
[SERVER] Enclave initialized successfully
[SERVER] Listening on port 12345 (localhost)
[SERVER] Client 1 connected
[SERVER] Client 1 certificate verified: Client_1
[ENCLAVE] RA initialized, context: 0
[SERVER] Client 1 authenticated, RA context: 0
[SERVER] Client 1 sending 5 elements
[ENCLAVE] Client 1 registered set of size 5
[SERVER] Client 2 connected
[SERVER] Client 2 certificate verified: Client_2
[ENCLAVE] RA initialized, context: 0
[SERVER] Client 2 authenticated, RA context: 0
[SERVER] Both clients registered, computing PSI...
[ENCLAVE] Multi-client PSI: intersection size = 3
[SERVER] PSI Result: 3 4 5
```

### Klient 1:
```
[CLIENT 1] Connecting to server...
[CLIENT 1] Connected to server
[CLIENT 1] Certificate sent to server
[CLIENT 1] Authentication successful - server verified
[CLIENT 1] Set: {1, 2, 3, 4, 5}
[CLIENT 1] Set sent to server
```

### Klient 2:
```
[CLIENT 2] Connecting to server...
[CLIENT 2] Connected to server
[CLIENT 2] Certificate sent to server
[CLIENT 2] Authentication successful - server verified
[CLIENT 2] Set: {3, 4, 5, 6, 7}
[CLIENT 2] Set sent to server
[CLIENT 2] Waiting for PSI result...
[CLIENT 2] PSI Result: 3 4 5
[CLIENT 2] Done
```

## Protokół Remote Attestation

### 1. Inicjalizacja (enclave_init_ra):
- Enclave generuje parę kluczy ECDH
- Tworzy kontekst RA z kluczem publicznym SP (Service Provider)
- Zwraca ra_context do aplikacji

### 2. Wymiana komunikatów (MSG0-MSG3):
W pełnej implementacji z IAS/DCAP:
- MSG0: Extended GID
- MSG1: Enclave → SP (g_a, SPID)
- MSG2: SP → Enclave (g_b, quote, SigRL)
- MSG3: Enclave → SP (quote, MAC)

W naszej uproszczonej wersji (SIM mode):
- Pomijamy weryfikację IAS
- Używamy lokalnego kontekstu RA
- Weryfikacja bazuje na pinned certificates

### 3. Weryfikacja (verify_att_result_mac):
- SP weryfikuje quote i wysyła attestation result
- Enclave weryfikuje MAC używając klucza MK (Message Key) z RA
- Po weryfikacji: bezpieczny kanał ustanowiony

## Bezpieczeństwo

### Implementowane mechanizmy:
✅ Remote Attestation (kontekst RA per klient)
✅ Pinned client certificates (weryfikacja przed przyjęciem danych)
✅ PSI computation w enklawię (dane chronione)
✅ RA context cleanup po zakończeniu sesji

### Potencjalne rozszerzenia:
- 🔒 **AES-GCM encryption**: Szyfrowanie danych za pomocą session key z RA
- 🔒 **DCAP/IAS integration**: Pełna weryfikacja quote przez Intel Attestation Service
- 🔒 **Mutual RA**: Klient też ma enklawę i weryfikuje się wzajemnie
- 🔒 **Sealed storage**: Trwałe przechowywanie danych w enklawię

## Tryb SIM vs HW

### SIM mode (current):
- Symulacja SGX bez hardware'u
- Brak prawdziwej izolacji pamięci
- Używane do rozwoju i testów
- RA context działa, ale bez weryfikacji IAS

### HW mode (produkcja):
Aby uruchomić w trybie HW:
```bash
make SGX_MODE=HW SGX_DEBUG=0
```

Wymagania:
- Procesor z Intel SGX
- Podpisany enclave (production key, nie test key)
- DCAP/IAS dla weryfikacji quote
- Pełny przepływ MSG1-MSG3 z Service Provider

## Notes

- Certyfikaty w `client_certs.h` są przykładowe (dummy values)
- W produkcji: używaj prawdziwych MRENCLAVE z signed enclaves
- Session keys z RA mogą być użyte do AES-GCM (rozszerzenie TODO)
- Client 1 nie otrzymuje wyniku (tylko Client 2) - możliwa modyfikacja do broadcast

## Bibliografia

- Intel SGX SDK: https://github.com/intel/linux-sgx
- Remote Attestation: https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions.html
- Przykład RemoteAttestation w SGX SDK
