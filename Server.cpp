/*
 * PSI_SGX Multi-Client Server with Remote Attestation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sgx_urts.h"
#include "sgx_ukey_exchange.h"
#include "Enclave_u.h"
#include "client_certs.h"
#include "sp/service_provider.h"

#define ENCLAVE_FILENAME "enclave.signed.so"
#define SGX_DEBUG_FLAG 1

sgx_enclave_id_t global_eid = 0;

// Weryfikacja certyfikatu klienta
int verify_client_cert(uint32_t client_id, const uint8_t *cert_hash)
{
    /* W trybie SIM: akceptuj client_id 1 lub 2 (atrapa walidacji)
     * W HW z prawdziwymi certami: odkomentuj porownanie hash ponizej */
    for (size_t i = 0; i < NUM_AUTHORIZED_CLIENTS; i++)
    {
        if (authorized_clients[i].client_id == client_id)
        {
            // sim
            printf("[SERVER] Client %d certificate accepted (SIM mode): %s\n",
                   client_id, authorized_clients[i].client_name);
            return 0;

            /* hw
            if (memcmp(authorized_clients[i].cert_hash, cert_hash, 32) == 0)
            {
                printf("[SERVER] Client %d certificate verified: %s\n",
                       client_id, authorized_clients[i].client_name);
                return 0;
            }
            else
            {
                printf("[SERVER] Client %d certificate MISMATCH!\n", client_id);
                return -1;
            }
            */
        }
    }
    printf("[SERVER] Client %d NOT in authorized list!\n", client_id);
    return -1;
}

#define PORT 12345
#define MAX_CLIENTS 2
#define SET_SIZE 10

typedef struct
{
    int socket;
    int client_id;
} client_info_t;

static int client_count = 0;
static int client_sockets[MAX_CLIENTS] = {0};
static sgx_ra_context_t client_ra_contexts[MAX_CLIENTS] = {0};
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void print_error_message(sgx_status_t ret)
{
    printf("Error code: 0x%X\n", ret);
}

int initialize_enclave(void)
{
    sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }
    printf("[SERVER] Enclave initialized successfully\n");
    return 0;
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

void *client_handler(void *arg)
{
    client_info_t *client = (client_info_t *)arg;
    uint32_t set[SET_SIZE];
    uint32_t set_size = 0;

    printf("[SERVER] Client %d connected\n", client->client_id);

    // Krok 1: odbierz hash certyfikatu klienta do weryfikacji
    uint8_t client_cert_hash[32];
    if (recv(client->socket, client_cert_hash, 32, 0) <= 0)
    {
        printf("[SERVER] Failed to receive certificate from client %d\n", client->client_id);
        close(client->socket);
        free(client);
        return NULL;
    }

    // zweryfikuj certyfikat
    if (verify_client_cert(client->client_id, client_cert_hash) != 0)
    {
        printf("[SERVER] Client %d authentication FAILED - closing connection\n", client->client_id);
        uint32_t reject = 0xFFFFFFFF;
        send(client->socket, &reject, sizeof(reject), 0);
        close(client->socket);
        free(client);
        return NULL;
    }

    // Krok 2: wyslij potwierdzenie uwierzytelnienia
    uint32_t auth_ok = 0x00000000;
    send(client->socket, &auth_ok, sizeof(auth_ok), 0);
    printf("[SERVER] Client %d certificate authenticated\n", client->client_id);

    // Krok 3: inicjalizacja kontekstu RA dla klienta
    sgx_ra_context_t ra_context = 0;
    sgx_status_t ret_status = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = enclave_init_ra(global_eid, &ret_status, 0, &ra_context);
    if (ret != SGX_SUCCESS || ret_status != SGX_SUCCESS)
    {
        printf("[SERVER] RA init failed: ret=0x%x, ret_status=0x%x\n", ret, ret_status);
        close(client->socket);
        free(client);
        return NULL;
    }
    printf("[SERVER] RA context initialized: %u\n", ra_context);

    // Krok 4: odbierz MSG1 od klienta
    sgx_ra_msg1_t msg1;
    if (recv(client->socket, &msg1, sizeof(sgx_ra_msg1_t), 0) <= 0)
    {
        printf("[SERVER] Failed to receive MSG1 from client %d\n", client->client_id);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }
    printf("[SERVER] MSG1 received from client %d\n", client->client_id);

    // Krok 5: wygeneruj MSG2 przez logike SP
    sample_ra_msg1_t sp_msg1;
    memcpy(&sp_msg1, &msg1, sizeof(sp_msg1));

    ra_samp_response_header_t *p_msg2_full = NULL;
    int sp_status = sp_ra_proc_msg1_req(&sp_msg1, sizeof(sp_msg1), &p_msg2_full);
    if (sp_status != SP_OK || !p_msg2_full || p_msg2_full->type != TYPE_RA_MSG2)
    {
        printf("[SERVER] SP failed to generate MSG2 (status=%d)\n", sp_status);
        if (p_msg2_full)
            free(p_msg2_full);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    uint32_t msg2_size = p_msg2_full->size;
    if (send(client->socket, &msg2_size, sizeof(msg2_size), 0) < 0)
    {
        printf("[SERVER] Failed to send MSG2 size\n");
        free(p_msg2_full);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    if (send(client->socket, p_msg2_full->body, msg2_size, 0) < 0)
    {
        printf("[SERVER] Failed to send MSG2\n");
        free(p_msg2_full);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }
    free(p_msg2_full);
    printf("[SERVER] MSG2 sent to client %d\n", client->client_id);

    // Krok 7: odbierz MSG3 od klienta
    uint32_t msg3_size;
    if (recv(client->socket, &msg3_size, sizeof(msg3_size), 0) <= 0)
    {
        printf("[SERVER] Failed to receive MSG3 size from client %d\n", client->client_id);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    sgx_ra_msg3_t *p_msg3 = (sgx_ra_msg3_t *)malloc(msg3_size);
    if (!p_msg3)
    {
        printf("[SERVER] Failed to allocate memory for MSG3\n");
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    if (recv(client->socket, p_msg3, msg3_size, 0) <= 0)
    {
        printf("[SERVER] Failed to receive MSG3 from client %d\n", client->client_id);
        free(p_msg3);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }
    printf("[SERVER] MSG3 received from client %d (size: %u)\n", client->client_id, msg3_size);

    // Krok 8: przetworz MSG3 po stronie SP
    ra_samp_response_header_t *p_att_result = NULL;
    sp_status = sp_ra_proc_msg3_req((sample_ra_msg3_t *)p_msg3, msg3_size, &p_att_result);
    free(p_msg3);

    if (sp_status != SP_OK || !p_att_result || p_att_result->type != TYPE_RA_ATT_RESULT)
    {
        printf("[SERVER] Failed to process MSG3 (sp_status=%d)\n", sp_status);
        uint32_t attestation_failed = 0xFFFFFFFF;
        send(client->socket, &attestation_failed, sizeof(attestation_failed), 0);
        if (p_att_result)
            free(p_att_result);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }
    free(p_att_result);
    printf("[SERVER] MSG3 verified successfully for client %d\n", client->client_id);

    // wyslij sukces atestacji
    uint32_t attestation_ok = 0x00000000;
    if (send(client->socket, &attestation_ok, sizeof(attestation_ok), 0) < 0)
    {
        printf("[SERVER] Failed to send attestation_ok to client %d\n", client->client_id);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    // wyslij MRENCLAVE serwera po stronie klienta
    sgx_report_t report;
    sgx_status_t rep_status = SGX_ERROR_UNEXPECTED;
    if (get_enclave_report(global_eid, &rep_status, NULL, &report) != SGX_SUCCESS || rep_status != SGX_SUCCESS)
    {
        printf("[SERVER] Failed to get enclave report for client %d\n", client->client_id);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    if (send(client->socket, report.body.mr_enclave.m, sizeof(report.body.mr_enclave.m), 0) < 0)
    {
        printf("[SERVER] Failed to send MRENCLAVE to client %d\n", client->client_id);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }
    printf("[SERVER] Attestation completed for client %d - RA protocol done!\n", client->client_id);

    // Handshake KX: odbierz pub klienta, wyslij pub serwera, wyprowadz klucz
    uint8_t client_pub[64];
    if (recv(client->socket, client_pub, sizeof(client_pub), 0) <= 0)
    {
        printf("[SERVER] Failed to receive client pubkey for client %d\n", client->client_id);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }
    uint8_t server_pub[64];
    sgx_status_t kx_status = SGX_ERROR_UNEXPECTED;
    sgx_status_t kx_ret = kx_server_init(global_eid, &kx_status, client->client_id, server_pub);
    if (kx_ret != SGX_SUCCESS || kx_status != SGX_SUCCESS)
    {
        printf("[SERVER] kx_server_init failed for client %d: ret=0x%x status=0x%x\n", client->client_id, kx_ret, kx_status);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }
    if (send(client->socket, server_pub, sizeof(server_pub), 0) < 0)
    {
        perror("send server pub");
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }
    kx_ret = kx_server_finish(global_eid, &kx_status, client->client_id, client_pub);
    if (kx_ret != SGX_SUCCESS || kx_status != SGX_SUCCESS)
    {
        printf("[SERVER] kx_server_finish failed for client %d: ret=0x%x status=0x%x\n", client->client_id, kx_ret, kx_status);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }
    printf("[SERVER] KX established for client %d\n", client->client_id);

    // odbierz zaszyfrowany zbior
    uint32_t cipher_size;
    if (recv(client->socket, &cipher_size, sizeof(cipher_size), 0) <= 0)
    {
        printf("[SERVER] Failed to receive cipher size from client %d\n", client->client_id);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    uint8_t *ciphertext = (uint8_t *)malloc(cipher_size);
    uint8_t gcm_tag[16];
    if (!ciphertext)
    {
        printf("[SERVER] Memory allocation failed\n");
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    if (recv(client->socket, ciphertext, cipher_size, 0) <= 0 ||
        recv(client->socket, gcm_tag, sizeof(gcm_tag), 0) <= 0)
    {
        printf("[SERVER] Failed to receive encrypted set from client %d\n", client->client_id);
        free(ciphertext);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    // odszyfruj w enklawie kluczem KX
    uint8_t iv[12] = {0};
    sgx_status_t dec_status = SGX_ERROR_UNEXPECTED;
    sgx_status_t dec_ret = kx_decrypt_server(global_eid, &dec_status,
                                             client->client_id,
                                             ciphertext, cipher_size,
                                             iv, gcm_tag,
                                             set, SET_SIZE, &set_size);
    free(ciphertext);

    if (dec_ret != SGX_SUCCESS || dec_status != SGX_SUCCESS)
    {
        printf("[SERVER] Failed to decrypt client %d set: ret=0x%x, status=0x%x\n", client->client_id, dec_ret, dec_status);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    printf("[SERVER] Client %d decrypted set: %u elements\n", client->client_id, set_size);

    // zarejestruj zbior w enklawie
    sgx_status_t retval2 = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret2 = ecall_register_client_set(global_eid, &retval2, client->client_id, set, set_size);
    if (ret2 != SGX_SUCCESS || retval2 != SGX_SUCCESS)
    {
        printf("[SERVER] Failed to register client %d set: ret=0x%x retval=0x%x\n", client->client_id, ret2, retval2);
        enclave_ra_close(global_eid, &ret_status, ra_context);
        close(client->socket);
        free(client);
        return NULL;
    }

    printf("[SERVER] Client %d set registered\n", client->client_id);

    pthread_mutex_lock(&lock);
    client_count++;
    int total_clients = client_count;
    pthread_mutex_unlock(&lock);

    pthread_mutex_lock(&lock);
    client_sockets[client->client_id - 1] = client->socket;
    client_ra_contexts[client->client_id - 1] = ra_context;
    pthread_mutex_unlock(&lock);

    // gdy obaj klienci zarejestrowani: policz PSI i wyslij zaszyfrowane wyniki
    if (total_clients == 2)
    {
        printf("[SERVER] Both clients registered, computing PSI...\n");

        uint32_t result[SET_SIZE];
        uint32_t result_count = 0;

        sgx_status_t ret_status3 = SGX_ERROR_UNEXPECTED;
        sgx_status_t ret3 = ecall_compute_psi_multi(global_eid, &ret_status3, result, &result_count);
        if (ret3 != SGX_SUCCESS || ret_status3 != SGX_SUCCESS)
        {
            printf("[SERVER] Failed to compute PSI: ret=0x%x, ret_status=0x%x\n", ret3, ret_status3);
        }
        else
        {
            printf("[SERVER] PSI Result (%u elements): ", result_count);
            for (uint32_t i = 0; i < result_count; i++)
            {
                printf("%u ", result[i]);
            }
            if (result_count == 0)
                printf("(empty)");
            printf("\n");

            // szyfruj i wyslij wynik do obu klientow
            pthread_mutex_lock(&lock);
            for (int i = 0; i < 2; i++)
            {
                if (client_sockets[i] > 0 && client_ra_contexts[i] != 0)
                {
                    uint32_t result_cipher_size = result_count * sizeof(uint32_t);
                    uint8_t *result_ciphertext = (uint8_t *)malloc(result_cipher_size);
                    uint8_t result_tag[16];

                    if (!result_ciphertext)
                    {
                        printf("[SERVER] Memory allocation failed for client %d\n", i + 1);
                        continue;
                    }

                    uint8_t iv2[12] = {0};
                    sgx_status_t enc_status = SGX_SUCCESS;
                    sgx_status_t enc_ret = kx_encrypt_server(global_eid, &enc_status,
                                                             (uint32_t)(i + 1),
                                                             result, result_count,
                                                             iv2,
                                                             result_ciphertext, result_cipher_size,
                                                             result_tag);
                    if (enc_ret != SGX_SUCCESS || enc_status != SGX_SUCCESS)
                    {
                        printf("[SERVER] Failed to encrypt result for client %d: ret=0x%x, status=0x%x\n", i + 1, enc_ret, enc_status);
                        free(result_ciphertext);
                        continue;
                    }

                    // wyslij wynik
                    send(client_sockets[i], &result_cipher_size, sizeof(result_cipher_size), 0);
                    send(client_sockets[i], result_ciphertext, result_cipher_size, 0);
                    send(client_sockets[i], result_tag, sizeof(result_tag), 0);
                    free(result_ciphertext);

                    printf("[SERVER] Encrypted results sent to client %d\n", i + 1);

                    sgx_status_t ra_close_status;
                    enclave_ra_close(global_eid, &ra_close_status, client_ra_contexts[i]);
                }
            }
            pthread_mutex_unlock(&lock);
        }

        close(client->socket);
        free(client);
        return NULL;
    }
    else
    {
        // pierwszy klient - utrzymaj polaczenie i RA, czekaj na drugiego
        printf("[SERVER] Client %d waiting for other client...\n", client->client_id);

        // czekaj az PSI sie skonczy
        while (1)
        {
            pthread_mutex_lock(&lock);
            int current_count = client_count;
            pthread_mutex_unlock(&lock);

            if (current_count >= 2)
            {
                // PSI policzone, poczekaj az wynik zostanie wyslany i RA zamkniety
                sleep(3);
                break;
            }

            sleep(1);
        }

        close(client->socket);
        free(client);
        return NULL;
    }

    close(client->socket);
    free(client);
    return NULL;
}

int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    if (initialize_enclave() < 0)
    {
        printf("[SERVER] Failed to initialize enclave\n");
        return -1;
    }

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        perror("socket");
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        return -1;
    }

    if (listen(server_socket, 2) < 0)
    {
        perror("listen");
        return -1;
    }

    printf("[SERVER] Listening on port %d (localhost)\n", PORT);

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0)
        {
            perror("accept");
            continue;
        }

        client_info_t *client = (client_info_t *)malloc(sizeof(client_info_t));
        client->socket = client_socket;
        client->client_id = i + 1;

        pthread_t thread;
        if (pthread_create(&thread, NULL, client_handler, client) != 0)
        {
            printf("[SERVER] Failed to create thread for client %d\n", i + 1);
            close(client_socket);
            free(client);
        }
        else
        {
            pthread_detach(thread);
        }
    }

    close(server_socket);

    sleep(2);

    sgx_destroy_enclave(global_eid);
    printf("[SERVER] Enclave destroyed\n");

    return 0;
}
