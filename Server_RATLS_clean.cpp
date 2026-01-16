/*
 * PSI_SGX Server with RA-TLS and E2E Encryption
 * ECDH-based key exchange + AES-128-GCM encryption
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ra_tls.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include "Enclave_u.h"
#include "sgx_urts.h"

extern "C" void ocall_print_string(const char *str) { printf("%s", str); }

#define PORT 12345
#define MAX_CLIENTS 10
#define SET_SIZE 10

sgx_enclave_id_t global_eid = 0;

static pthread_mutex_t psi_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t psi_cond = PTHREAD_COND_INITIALIZER;
static int clients_ready = 0;

typedef struct
{
    mbedtls_ssl_context *ssl;
    mbedtls_net_context *client_fd;
    int client_id;
    pthread_t thread;
} client_info_t;

int initialize_enclave(void)
{
    sgx_status_t ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG,
                                          NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        printf("[SERVER] Failed to create enclave: 0x%x\n", ret);
        return -1;
    }
    printf("[SERVER] Enclave created successfully\n");
    return 0;
}

void *client_handler(void *arg)
{
    client_info_t *client = (client_info_t *)arg;
    mbedtls_ssl_context *ssl = client->ssl;
    int client_id = client->client_id;
    int ret;
    sgx_status_t status, enclave_ret;

    // Buffers
    uint8_t server_pubkey[64];
    uint8_t client_pubkey[64];
    uint8_t client_pubkey_le[64];
    uint8_t iv[12];
    uint8_t gcm_tag[16];
    unsigned char data[1024];
    size_t data_received = 0;
    uint32_t data_size = 0;

    uint32_t decrypted_set[SET_SIZE];
    uint32_t decrypted_size = 0;

    uint8_t result_iv[12];
    uint8_t encrypted_result[512];
    uint8_t result_tag[16];
    uint32_t psi_result[SET_SIZE];
    uint32_t psi_result_size = 0;

    printf("[SERVER] Client %d: Connected\n", client_id);

    // TLS handshake
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf("[SERVER] Client %d: TLS handshake failed: 0x%x\n", client_id, ret);
            goto cleanup;
        }
    }
    printf("[SERVER] Client %d: TLS handshake OK\n", client_id);

    // Generate server ECDH pubkey in enclave
    status = kx_server_init(global_eid, &enclave_ret, client_id, server_pubkey);
    if (status != SGX_SUCCESS || enclave_ret != SGX_SUCCESS)
    {
        printf("[SERVER] Client %d: kx_server_init failed: 0x%x / 0x%x\n", client_id, status, enclave_ret);
        goto cleanup;
    }
    printf("[SERVER] Client %d: Server pubkey generated\n", client_id);

    // Send server pubkey to client
    ret = mbedtls_ssl_write(ssl, server_pubkey, 64);
    if (ret != 64)
    {
        printf("[SERVER] Client %d: Failed to send pubkey\n", client_id);
        goto cleanup;
    }
    printf("[SERVER] Client %d: Server pubkey sent\n", client_id);

    // Receive client pubkey (big-endian from network)
    ret = mbedtls_ssl_read(ssl, client_pubkey, 64);
    if (ret != 64)
    {
        printf("[SERVER] Client %d: Failed to receive client pubkey\n", client_id);
        goto cleanup;
    }
    printf("[SERVER] Client %d: Client pubkey received\n", client_id);

    // Convert BE to LE for enclave
    for (int i = 0; i < 32; i++)
    {
        client_pubkey_le[i] = client_pubkey[31 - i];
        client_pubkey_le[32 + i] = client_pubkey[63 - i];
    }

    // Complete ECDH in enclave
    status = kx_server_finish(global_eid, &enclave_ret, client_id, client_pubkey_le);
    if (status != SGX_SUCCESS)
    {
        printf("[SERVER] Client %d: kx_server_finish OCALL failed: 0x%x\n", client_id, status);
        goto cleanup;
    }
    if (enclave_ret != SGX_SUCCESS)
    {
        printf("[SERVER] Client %d: ECDH finish failed: 0x%x\n", client_id, enclave_ret);
        goto cleanup;
    }
    printf("[SERVER] Client %d: ECDH complete\n", client_id);

    // Receive encrypted data [IV:12][size:4][blob][tag:16]
    ret = mbedtls_ssl_read(ssl, iv, 12);
    if (ret != 12)
    {
        printf("[SERVER] Client %d: Failed to read IV\n", client_id);
        goto cleanup;
    }

    ret = mbedtls_ssl_read(ssl, (unsigned char *)&data_size, 4);
    if (ret != 4)
    {
        printf("[SERVER] Client %d: Failed to read data size\n", client_id);
        goto cleanup;
    }

    printf("[SERVER] Client %d: Expecting %u bytes\n", client_id, data_size);

    data_received = 0;
    while (data_received < data_size)
    {
        ret = mbedtls_ssl_read(ssl, data + data_received, data_size - data_received);
        if (ret <= 0)
        {
            printf("[SERVER] Client %d: Read error\n", client_id);
            goto cleanup;
        }
        data_received += ret;
    }

    ret = mbedtls_ssl_read(ssl, gcm_tag, 16);
    if (ret != 16)
    {
        printf("[SERVER] Client %d: Failed to read GCM tag\n", client_id);
        goto cleanup;
    }
    printf("[SERVER] Client %d: Received encrypted data (%u bytes)\n", client_id, data_size);

    // Decrypt in enclave
    status = kx_decrypt_server(global_eid, &enclave_ret, client_id,
                               data, data_size, iv, gcm_tag,
                               decrypted_set, SET_SIZE, &decrypted_size);
    if (status != SGX_SUCCESS)
    {
        printf("[SERVER] Client %d: kx_decrypt_server failed: 0x%x\n", client_id, status);
        goto cleanup;
    }
    if (enclave_ret != SGX_SUCCESS)
    {
        printf("[SERVER] Client %d: Decryption failed: 0x%x\n", client_id, enclave_ret);
        goto cleanup;
    }
    printf("[SERVER] Client %d: Decrypted %u elements\n", client_id, decrypted_size);

    // Register client set
    status = ecall_register_client_set(global_eid, &enclave_ret, client_id, decrypted_set, decrypted_size);
    if (status != SGX_SUCCESS || enclave_ret != SGX_SUCCESS)
    {
        printf("[SERVER] Client %d: register failed: 0x%x / 0x%x\n", client_id, status, enclave_ret);
        goto cleanup;
    }

    // Wait for both clients
    pthread_mutex_lock(&psi_lock);
    clients_ready++;
    if (clients_ready < 2)
    {
        pthread_cond_wait(&psi_cond, &psi_lock);
    }
    else
    {
        pthread_cond_broadcast(&psi_cond);
    }
    pthread_mutex_unlock(&psi_lock);

    // Compute PSI
    status = ecall_compute_psi_multi(global_eid, &enclave_ret, psi_result, &psi_result_size);
    if (status != SGX_SUCCESS || enclave_ret != SGX_SUCCESS)
    {
        printf("[SERVER] Client %d: PSI failed: 0x%x / 0x%x\n", client_id, status, enclave_ret);
        goto cleanup;
    }
    printf("[SERVER] Client %d: PSI result: %u elements\n", client_id, psi_result_size);

    // Encrypt result
    for (int i = 0; i < 12; i++)
        result_iv[i] = rand() & 0xFF;

    status = kx_encrypt_server(global_eid, &enclave_ret, client_id,
                               psi_result, psi_result_size, result_iv,
                               encrypted_result, sizeof(encrypted_result), result_tag);
    if (status != SGX_SUCCESS || enclave_ret != SGX_SUCCESS)
    {
        printf("[SERVER] Client %d: Encrypt failed: 0x%x / 0x%x\n", client_id, status, enclave_ret);
        goto cleanup;
    }
    printf("[SERVER] Client %d: Result encrypted\n", client_id);

    // Send encrypted result
    ret = mbedtls_ssl_write(ssl, result_iv, 12);
    ret = mbedtls_ssl_write(ssl, (unsigned char *)&psi_result_size, 4);
    ret = mbedtls_ssl_write(ssl, encrypted_result, psi_result_size * 4);
    ret = mbedtls_ssl_write(ssl, result_tag, 16);
    printf("[SERVER] Client %d: Result sent\n", client_id);

cleanup:
    mbedtls_ssl_close_notify(ssl);
    mbedtls_ssl_free(ssl);
    free(ssl);
    if (client->client_fd)
    {
        mbedtls_net_free(client->client_fd);
        free(client->client_fd);
    }
    free(client);
    printf("[SERVER] Client %d: Closed\n", client_id);
    return NULL;
}

int main()
{
    printf("=== PSI_SGX Server with RA-TLS ===\n");

    if (initialize_enclave() < 0)
        return 1;

    // Generate fake RA-TLS cert
    uint8_t cert_der[1024];
    uint32_t cert_len = 0;
    if (generate_fake_ratls_cert(cert_der, &cert_len) < 0)
    {
        printf("[SERVER] Failed to generate cert\n");
        return 1;
    }
    printf("[SERVER] RA-TLS cert generated (%u bytes)\n", cert_len);

    // Setup mbedTLS
    mbedtls_net_context listen_fd;
    mbedtls_net_init(&listen_fd);

    if (mbedtls_net_bind(&listen_fd, NULL, "12345", MBEDTLS_NET_PROTO_TCP) != 0)
    {
        printf("[SERVER] Failed to bind\n");
        return 1;
    }
    printf("[SERVER] Listening on port 12345\n");

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)"PSI", 3);

    mbedtls_x509_crt srvcert;
    mbedtls_pk_context srvkey;
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&srvkey);

    if (mbedtls_x509_crt_parse_der(&srvcert, cert_der, cert_len) != 0)
    {
        printf("[SERVER] Failed to parse cert\n");
        return 1;
    }

    if (load_fake_ratls_key(&srvkey) < 0)
    {
        printf("[SERVER] Failed to load key\n");
        return 1;
    }
    printf("[SERVER] Cert and key loaded\n");

    int client_count = 0;
    while (1)
    {
        mbedtls_net_context *client_fd = (mbedtls_net_context *)malloc(sizeof(mbedtls_net_context));
        mbedtls_net_init(client_fd);

        if (mbedtls_net_accept(&listen_fd, client_fd, NULL, 0, NULL) != 0)
        {
            free(client_fd);
            continue;
        }

        client_count++;
        int client_id = (client_count % 2) + 1; // Alternate between 1 and 2

        mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)malloc(sizeof(mbedtls_ssl_context));
        mbedtls_ssl_init(ssl);

        mbedtls_ssl_config *conf = (mbedtls_ssl_config *)malloc(sizeof(mbedtls_ssl_config));
        mbedtls_ssl_config_init(conf);
        mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        mbedtls_ssl_conf_own_cert(conf, &srvcert, &srvkey);
        mbedtls_ssl_setup(ssl, conf);
        mbedtls_ssl_set_bio(ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        client_info_t *info = (client_info_t *)malloc(sizeof(client_info_t));
        info->ssl = ssl;
        info->client_fd = client_fd;
        info->client_id = client_id;

        pthread_create(&info->thread, NULL, client_handler, (void *)info);
    }

    return 0;
}
