/*
 * PSI_SGX Client - klient z enklawa do Remote Attestation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "client_certs.h"
#include "server_mrenclave.h"
#include "EnclaveClient_u.h"
#include "sgx_urts.h"
#include "sgx_ukey_exchange.h"
#include "sp/service_provider.h"

#define PORT 12345
#define SET_SIZE 10
#define ENCLAVE_FILENAME "enclaveclient.signed.so"

sgx_enclave_id_t global_eid = 0;

int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("Failed to create enclave. Error code: 0x%x\n", ret);
        return -1;
    }
    printf("[CLIENT] Enclave created successfully\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <client_id> (1 or 2)\n", argv[0]);
        return -1;
    }

    int client_id = atoi(argv[1]);
    if (client_id != 1 && client_id != 2)
    {
        printf("Invalid client_id. Must be 1 or 2\n");
        return -1;
    }

    if (initialize_enclave() < 0)
    {
        return -1;
    }

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        perror("socket");
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // laczenie z serwerem
    printf("[CLIENT %d] Connecting to server...\n", client_id);
    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        close(socket_fd);
        return -1;
    }

    printf("[CLIENT %d] Connected to server\n", client_id);

    // Krok 1: wyslij hash certyfikatu klienta do uwierzytelnienia
    const uint8_t *my_cert_hash = authorized_clients[client_id - 1].cert_hash;
    if (send(socket_fd, my_cert_hash, 32, 0) < 0)
    {
        perror("send certificate");
        close(socket_fd);
        return -1;
    }
    printf("[CLIENT %d] Certificate sent to server\n", client_id);

    // Krok 2: odbierz wynik uwierzytelnienia
    uint32_t auth_response;
    if (recv(socket_fd, &auth_response, sizeof(auth_response), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive auth response\n", client_id);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (auth_response != 0x00000000)
    {
        printf("[CLIENT %d] Authentication REJECTED by server!\n", client_id);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] Authentication successful - server verified\n", client_id);

    // Krok 3: zainicjuj RA w enklawie
    sgx_status_t ret, ra_status;
    sgx_ra_context_t ra_context;

    ret = enclave_init_ra(global_eid, &ra_status, 0, &ra_context);
    if (ret != SGX_SUCCESS || ra_status != SGX_SUCCESS)
    {
        printf("[CLIENT %d] Failed to initialize RA. Error: 0x%x\n", client_id, ra_status);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] RA initialized, context: %u\n", client_id, ra_context);

    // Krok 4: wygeneruj MSG1
    sgx_ra_msg1_t msg1;
    ret = sgx_ra_get_msg1(ra_context, global_eid, sgx_ra_get_ga, &msg1);
    if (ret != SGX_SUCCESS)
    {
        printf("[CLIENT %d] Failed to generate MSG1. Error: 0x%x\n", client_id, ret);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] MSG1 generated\n", client_id);

    // Krok 5: wyslij MSG1 do serwera
    if (send(socket_fd, &msg1, sizeof(sgx_ra_msg1_t), 0) < 0)
    {
        perror("send MSG1");
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] MSG1 sent to server\n", client_id);

    // Krok 6: odbierz MSG2 z serwera
    uint32_t msg2_size;
    if (recv(socket_fd, &msg2_size, sizeof(msg2_size), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive MSG2 size\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    sgx_ra_msg2_t *p_msg2 = (sgx_ra_msg2_t *)malloc(msg2_size);
    if (!p_msg2)
    {
        printf("[CLIENT %d] Failed to allocate memory for MSG2\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (recv(socket_fd, p_msg2, msg2_size, 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive MSG2\n", client_id);
        free(p_msg2);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] MSG2 received (size: %u)\n", client_id, msg2_size);

    // Krok 7: przetworz MSG2 i wygeneruj MSG3
    sgx_ra_msg3_t *p_msg3 = NULL;
    uint32_t msg3_size = 0;

    ret = sgx_ra_proc_msg2(ra_context, global_eid, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
                           p_msg2, msg2_size, &p_msg3, &msg3_size);
    free(p_msg2);

    if (ret != SGX_SUCCESS || !p_msg3)
    {
        printf("[CLIENT %d] Failed to process MSG2. Error: 0x%x\n", client_id, ret);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] MSG3 generated (size: %u)\n", client_id, msg3_size);

    // Krok 8: wyslij MSG3 do serwera
    if (send(socket_fd, &msg3_size, sizeof(msg3_size), 0) < 0)
    {
        perror("send MSG3 size");
        free(p_msg3);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (send(socket_fd, p_msg3, msg3_size, 0) < 0)
    {
        perror("send MSG3");
        free(p_msg3);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    free(p_msg3);
    printf("[CLIENT %d] MSG3 sent - RA protocol completed!\n", client_id);

    // Krok 9: odbierz wynik atestacji
    uint32_t attestation_result;
    if (recv(socket_fd, &attestation_result, sizeof(attestation_result), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive attestation result\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (attestation_result != 0x00000000)
    {
        printf("[CLIENT %d] Server attestation FAILED!\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    // Krok 10: odbierz MRENCLAVE serwera i zweryfikuj
    uint8_t server_mrenclave[32];
    if (recv(socket_fd, server_mrenclave, sizeof(server_mrenclave), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive server MRENCLAVE\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    int match = 0;

    int expected_nonzero = 0;
    for (int i = 0; i < 32; i++)
        expected_nonzero |= expected_server_mrenclave[i];

    if (expected_nonzero)
    {
        sgx_status_t m_status = verify_server_mrenclave(global_eid, &ra_status,
                                                        ra_context,
                                                        server_mrenclave,
                                                        const_cast<uint8_t *>(expected_server_mrenclave),
                                                        &match);
        if (m_status != SGX_SUCCESS || ra_status != SGX_SUCCESS || !match)
        {
            printf("[CLIENT %d] Server MRENCLAVE mismatch!\n", client_id);
            enclave_ra_close(global_eid, &ra_status, ra_context);
            close(socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        }
        printf("[CLIENT %d] Server MRENCLAVE pinned and verified.\n", client_id);
    }
    else
    {
        printf("[CLIENT %d] Warning: expected_server_mrenclave not set (all zeros); skipping MRENCLAVE pin check.\n", client_id);
    }

    printf("[CLIENT %d] Server attestation successful - server code verified!\n", client_id);

    // klient weryfikuje serwer
    printf("[CLIENT %d] Starting mutual attestation - verifying server enclave...\n", client_id);

    // odbierz MSG1 od serwera
    sgx_ra_msg1_t server_msg1;
    if (recv(socket_fd, &server_msg1, sizeof(server_msg1), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive server MSG1\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] Server MSG1 received\n", client_id);

    // przetworzenie MSG1 serwera przez SP
    sample_ra_msg1_t sp_server_msg1;
    memcpy(&sp_server_msg1, &server_msg1, sizeof(sp_server_msg1));

    ra_samp_response_header_t *p_server_msg2_full = NULL;
    int sp_status = sp_ra_proc_msg1_req(&sp_server_msg1, sizeof(sp_server_msg1), &p_server_msg2_full);
    if (sp_status != SP_OK || !p_server_msg2_full || p_server_msg2_full->type != TYPE_RA_MSG2)
    {
        printf("[CLIENT %d] Failed to generate server MSG2 (sp_status=%d)\n", client_id, sp_status);
        if (p_server_msg2_full)
            free(p_server_msg2_full);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    // wyslij MSG2 do serwera
    uint32_t server_msg2_size = p_server_msg2_full->size;
    if (send(socket_fd, &server_msg2_size, sizeof(server_msg2_size), 0) < 0 ||
        send(socket_fd, p_server_msg2_full->body, server_msg2_size, 0) < 0)
    {
        printf("[CLIENT %d] Failed to send server MSG2\n", client_id);
        free(p_server_msg2_full);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    free(p_server_msg2_full);
    printf("[CLIENT %d] Server MSG2 sent\n", client_id);

    // odbierz MSG3 od serwera
    uint32_t server_msg3_size;
    if (recv(socket_fd, &server_msg3_size, sizeof(server_msg3_size), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive server MSG3 size\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    sgx_ra_msg3_t *p_server_msg3 = (sgx_ra_msg3_t *)malloc(server_msg3_size);
    if (!p_server_msg3)
    {
        printf("[CLIENT %d] Memory allocation failed for server MSG3\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    if (recv(socket_fd, p_server_msg3, server_msg3_size, 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive server MSG3\n", client_id);
        free(p_server_msg3);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] Server MSG3 received (size: %u)\n", client_id, server_msg3_size);

    // weryfikuj MSG3 serwera przez SP (klient jako SP)
    ra_samp_response_header_t *p_server_att_result = NULL;
    sp_status = sp_ra_proc_msg3_req((sample_ra_msg3_t *)p_server_msg3, server_msg3_size, &p_server_att_result);
    free(p_server_msg3);

    if (sp_status != SP_OK || !p_server_att_result || p_server_att_result->type != TYPE_RA_ATT_RESULT)
    {
        printf("[CLIENT %d] Server attestation verification FAILED (sp_status=%d)\n", client_id, sp_status);
        uint32_t server_att_failed = 0xFFFFFFFF;
        send(socket_fd, &server_att_failed, sizeof(server_att_failed), 0);
        if (p_server_att_result)
            free(p_server_att_result);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    free(p_server_att_result);
    printf("[CLIENT %d] Server MSG3 verified - server enclave is AUTHENTIC!\n", client_id);

    // wyslij potwierdzenie weryfikacji serwera
    uint32_t server_att_ok = 0x00000000;
    if (send(socket_fd, &server_att_ok, sizeof(server_att_ok), 0) < 0)
    {
        printf("[CLIENT %d] Failed to send server attestation result\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    printf("[CLIENT %d] ATTESTATION COMPLETE\n", client_id);

    // Handshake ECDH (KX) wewnatrz enklaw po RA – klucz tylko w enklawach
    uint8_t client_pub[64];
    sgx_status_t kx_status = SGX_ERROR_UNEXPECTED;
    ret = kx_client_init(global_eid, &kx_status, client_pub);
    if (ret != SGX_SUCCESS || kx_status != SGX_SUCCESS)
    {
        printf("[CLIENT %d] kx_client_init failed: ret=0x%x status=0x%x\n", client_id, ret, kx_status);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    // wyślij pub klienta i odbierz pub serwera
    if (send(socket_fd, client_pub, sizeof(client_pub), 0) < 0)
    {
        perror("send client pub");
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    uint8_t server_pub[64];
    if (recv(socket_fd, server_pub, sizeof(server_pub), 0) <= 0)
    {
        printf("[CLIENT %d] Failed to receive server pubkey\n", client_id);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    ret = kx_client_finish(global_eid, &kx_status, server_pub);
    if (ret != SGX_SUCCESS || kx_status != SGX_SUCCESS)
    {
        printf("[CLIENT %d] kx_client_finish failed: ret=0x%x status=0x%x\n", client_id, ret, kx_status);
        enclave_ra_close(global_eid, &ra_status, ra_context);
        close(socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("[CLIENT %d] KX established – payload key inside enclaves only\n", client_id);

    // przygotowanie zbioru danych
    uint32_t set[SET_SIZE];
    uint32_t set_size;

    if (client_id == 1)
    {
        // {1, 2, 3, 4, 5}
        uint32_t data[] = {1, 2, 3, 4, 5};
        set_size = 5;
        memcpy(set, data, set_size * sizeof(uint32_t));
        printf("[CLIENT %d] Set: {1, 2, 3, 4, 5}\n", client_id);
    }
    else
    {
        // {3, 4, 5, 6, 7}
        uint32_t data[] = {3, 4, 5, 6, 7};
        set_size = 5;
        memcpy(set, data, set_size * sizeof(uint32_t));
        printf("[CLIENT %d] Set: {3, 4, 5, 6, 7}\n", client_id);
    }

    // szyfrowanie zbior w enklawie
    uint8_t iv[12] = {0};
    uint32_t cipher_size = set_size * sizeof(uint32_t);
    uint8_t *ciphertext = (uint8_t *)malloc(cipher_size);
    uint8_t gcm_tag[16];

    if (!ciphertext)
    {
        printf("[CLIENT %d] Memory allocation failed\n", client_id);
        close(socket_fd);
        return -1;
    }

    // szyfruj zbiory
    ret = kx_encrypt_client(global_eid, &kx_status,
                            set, set_size, iv,
                            ciphertext, cipher_size, gcm_tag);
    if (ret != SGX_SUCCESS || kx_status != SGX_SUCCESS)
    {
        printf("[CLIENT %d] Failed to encrypt set with KX: ret=0x%x, status=0x%x\n", client_id, ret, kx_status);
        free(ciphertext);
        close(socket_fd);
        return -1;
    }

    // wysylanie szyfrogramu
    if (send(socket_fd, &cipher_size, sizeof(cipher_size), 0) < 0 ||
        send(socket_fd, ciphertext, cipher_size, 0) < 0 ||
        send(socket_fd, gcm_tag, sizeof(gcm_tag), 0) < 0)
    {
        perror("send encrypted set");
        free(ciphertext);
        close(socket_fd);
        return -1;
    }
    free(ciphertext);

    printf("[CLIENT %d] Encrypted set sent to server\n", client_id);

    // czekaj na zaszyfrowany wynik PSI
    printf("[CLIENT %d] Waiting for encrypted PSI result...\n", client_id);
    uint32_t result_cipher_size;
    // aktywne czekanie na dane od serwera
    while (1)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(socket_fd, &rfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 500 * 1000; // 500ms
        int sel = select(socket_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0)
        {
            if (errno == EINTR)
                continue;
            perror("select");
            close(socket_fd);
            return -1;
        }
        if (sel > 0 && FD_ISSET(socket_fd, &rfds))
        {
            ssize_t r = recv(socket_fd, &result_cipher_size, sizeof(result_cipher_size), 0);
            if (r <= 0)
            {
                printf("[CLIENT %d] Connection closed before result size\n", client_id);
                close(socket_fd);
                return -1;
            }
            break;
        }
        // brak danych – nadal czekaj
    }

    uint8_t *result_ciphertext = (uint8_t *)malloc(result_cipher_size);
    uint8_t result_tag[16];
    if (!result_ciphertext)
    {
        printf("[CLIENT %d] Memory allocation failed\n", client_id);
        close(socket_fd);
        return -1;
    }

    // odbierz dokladnie result_cipher_size bajtow szyfrogramu
    size_t got = 0;
    while (got < result_cipher_size)
    {
        ssize_t r = recv(socket_fd, result_ciphertext + got, result_cipher_size - got, 0);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            perror("recv ciphertext");
            free(result_ciphertext);
            close(socket_fd);
            return -1;
        }
        if (r == 0)
        {
            printf("[CLIENT %d] Connection closed while receiving result ciphertext\n", client_id);
            free(result_ciphertext);
            close(socket_fd);
            return -1;
        }
        got += (size_t)r;
    }
    // odbierz 16 bajtow taga
    got = 0;
    while (got < sizeof(result_tag))
    {
        ssize_t r = recv(socket_fd, result_tag + got, sizeof(result_tag) - got, 0);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            perror("recv tag");
            free(result_ciphertext);
            close(socket_fd);
            return -1;
        }
        if (r == 0)
        {
            printf("[CLIENT %d] Connection closed while receiving result tag\n", client_id);
            free(result_ciphertext);
            close(socket_fd);
            return -1;
        }
        got += (size_t)r;
    }

    // odszyfruj wynik w enklawie (KX)
    uint32_t result[SET_SIZE];
    uint32_t result_count = 0;
    ret = kx_decrypt_client(global_eid, &kx_status,
                            result_ciphertext, result_cipher_size, iv, result_tag,
                            result, SET_SIZE, &result_count);
    free(result_ciphertext);

    if (ret != SGX_SUCCESS || ra_status != SGX_SUCCESS)
    {
        printf("[CLIENT %d] Failed to decrypt result with RA SK: ret=0x%x, ra_status=0x%x\n", client_id, ret, ra_status);
        close(socket_fd);
        return -1;
    }

    printf("[CLIENT %d] PSI Result: ", client_id);
    for (uint32_t i = 0; i < result_count; i++)
    {
        printf("%u ", result[i]);
    }
    printf("\n");

    enclave_ra_close(global_eid, &ra_status, ra_context);
    close(socket_fd);
    sgx_destroy_enclave(global_eid);
    printf("[CLIENT %d] Done\n", client_id);
    return 0;
}
