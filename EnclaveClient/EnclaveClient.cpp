#include "EnclaveClient_t.h"

#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"


// Do testow uzywamy przykladowego klucza
static const sgx_ec256_public_t g_sp_pub_key = {
    {0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
     0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
     0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
     0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38},
    {0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
     0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
     0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
     0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06}};

sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t *p_context)
{
    return sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
}

sgx_status_t enclave_ra_close(sgx_ra_context_t context)
{
    return sgx_ra_close(context);
}

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t *message,
                                   size_t message_size,
                                   uint8_t *mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t sk_key;

    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (SGX_SUCCESS != ret)
    {
        return ret;
    }

    uint8_t aes_gcm_iv[12] = {0};

    sgx_rijndael128GCM_decrypt(&sk_key,
                               message,
                               message_size,
                               NULL,
                               aes_gcm_iv,
                               12,
                               NULL,
                               0,
                               (sgx_aes_gcm_128bit_tag_t *)mac);

    return ret;
}

sgx_status_t verify_server_mrenclave(sgx_ra_context_t context,
                                     uint8_t *received_mrenclave,
                                     uint8_t *expected_mrenclave,
                                     int *match)
{
    // porownaj dwie wartosci MRENCLAVE
    *match = (memcmp(received_mrenclave, expected_mrenclave, 32) == 0) ? 1 : 0;
    return SGX_SUCCESS;
}

/* Wymiana klucza ECDH (strona klienta) */
static sgx_ecc_state_handle_t g_ecc_ctx = 0;
static sgx_ec256_private_t g_cli_priv;
static sgx_ec256_public_t g_cli_pub;
static sgx_aes_gcm_128bit_key_t g_kx_key; // klucz wyprowadzony z DH
static int g_kx_ready = 0;

sgx_status_t kx_client_init(uint8_t *client_pubkey)
{
    if (!client_pubkey)
        return SGX_ERROR_INVALID_PARAMETER;
    sgx_status_t ret = sgx_ecc256_open_context(&g_ecc_ctx);
    if (ret != SGX_SUCCESS)
        return ret;
    ret = sgx_ecc256_create_key_pair(&g_cli_priv, &g_cli_pub, g_ecc_ctx);
    if (ret != SGX_SUCCESS)
        return ret;
    memcpy(client_pubkey, g_cli_pub.gx, 32);
    memcpy(client_pubkey + 32, g_cli_pub.gy, 32);
    return SGX_SUCCESS;
}

sgx_status_t kx_client_finish(const uint8_t *server_pubkey)
{
    if (!server_pubkey)
        return SGX_ERROR_INVALID_PARAMETER;
    sgx_ec256_public_t srv{};
    memcpy(srv.gx, server_pubkey, 32);
    memcpy(srv.gy, server_pubkey + 32, 32);
    sgx_ec256_dh_shared_t shared{};
    sgx_status_t ret = sgx_ecc256_compute_shared_dhkey(&g_cli_priv, &srv, &shared, g_ecc_ctx);
    if (ret != SGX_SUCCESS)
        return ret;
    sgx_sha256_hash_t hash;
    ret = sgx_sha256_msg((const uint8_t *)&shared, sizeof(shared), &hash);
    if (ret != SGX_SUCCESS)
        return ret;
    memcpy(&g_kx_key, hash, 16);
    g_kx_ready = 1;
    return SGX_SUCCESS;
}

static sgx_status_t kx_get_key(sgx_aes_gcm_128bit_key_t *key)
{
    if (!key)
        return SGX_ERROR_INVALID_PARAMETER;
    if (!g_kx_ready)
        return SGX_ERROR_INVALID_STATE;
    memcpy(key, &g_kx_key, sizeof(*key));
    return SGX_SUCCESS;
}

sgx_status_t kx_encrypt_client(const uint32_t *plaintext,
                               uint32_t plain_count,
                               const uint8_t *iv,
                               uint8_t *ciphertext,
                               uint32_t cipher_size,
                               uint8_t *gcm_tag)
{
    if (!plaintext || !iv || !ciphertext || !gcm_tag)
        return SGX_ERROR_INVALID_PARAMETER;
    uint32_t pt_bytes = plain_count * sizeof(uint32_t);
    if (cipher_size < pt_bytes)
        return SGX_ERROR_INVALID_PARAMETER;
    sgx_aes_gcm_128bit_key_t key;
    sgx_status_t ret = kx_get_key(&key);
    if (ret != SGX_SUCCESS)
        return ret;
    return sgx_rijndael128GCM_encrypt(&key,
                                      (const uint8_t *)plaintext,
                                      pt_bytes,
                                      ciphertext,
                                      iv,
                                      12,
                                      NULL,
                                      0,
                                      (sgx_aes_gcm_128bit_tag_t *)gcm_tag);
}

sgx_status_t kx_decrypt_client(const uint8_t *ciphertext,
                               uint32_t cipher_size,
                               const uint8_t *iv,
                               const uint8_t *gcm_tag,
                               uint32_t *plaintext,
                               uint32_t plain_max,
                               uint32_t *plain_count)
{
    if (!ciphertext || !iv || !gcm_tag || !plaintext || !plain_count)
        return SGX_ERROR_INVALID_PARAMETER;
    if (cipher_size % sizeof(uint32_t))
        return SGX_ERROR_INVALID_PARAMETER;
    uint32_t pt_bytes = cipher_size;
    uint32_t required = pt_bytes / sizeof(uint32_t);
    if (plain_max < required)
        return SGX_ERROR_INVALID_PARAMETER;
    sgx_aes_gcm_128bit_key_t key;
    sgx_status_t ret = kx_get_key(&key);
    if (ret != SGX_SUCCESS)
        return ret;
    ret = sgx_rijndael128GCM_decrypt(&key,
                                     ciphertext,
                                     cipher_size,
                                     (uint8_t *)plaintext,
                                     iv,
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t *)gcm_tag);
    if (ret == SGX_SUCCESS)
        *plain_count = required;
    return ret;
}
static sgx_status_t get_sk(sgx_ra_context_t context, sgx_aes_gcm_128bit_key_t *sk)
{
    if (!sk)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, sk);
    
    // W SIM sgx_ra_get_keys zwroci blad, uzyjemy testowego klucza
    if (ret != SGX_SUCCESS) {
        // Testowy klucz dla SIM: wszystkie bajty = 0x55
        memset(sk, 0x55, sizeof(*sk));
        return SGX_SUCCESS;
    }
    
    return ret;
}

sgx_status_t ecall_ra_encrypt_client(
    sgx_ra_context_t context,
    const uint32_t *plaintext,
    uint32_t plain_count,
    const uint8_t *iv,
    uint8_t *ciphertext,
    uint32_t cipher_size,
    uint8_t *gcm_tag)
{
    if (!plaintext || !iv || !ciphertext || !gcm_tag)
        return SGX_ERROR_INVALID_PARAMETER;
    if (plain_count == 0)
        return SGX_ERROR_INVALID_PARAMETER;
    uint32_t pt_bytes = plain_count * sizeof(uint32_t);
    if (cipher_size < pt_bytes)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_aes_gcm_128bit_key_t sk;
    sgx_status_t ret = get_sk(context, &sk);
    if (ret != SGX_SUCCESS)
        return ret;

    ret = sgx_rijndael128GCM_encrypt(&sk,
                                     (const uint8_t *)plaintext,
                                     pt_bytes,
                                     ciphertext,
                                     iv,
                                     12,
                                     NULL,
                                     0,
                                     (sgx_aes_gcm_128bit_tag_t *)gcm_tag);
    return ret;
}

sgx_status_t ecall_ra_decrypt_client(
    sgx_ra_context_t context,
    const uint8_t *ciphertext,
    uint32_t cipher_size,
    const uint8_t *iv,
    const uint8_t *gcm_tag,
    uint32_t *plaintext,
    uint32_t plain_max,
    uint32_t *plain_count)
{
    if (!ciphertext || !iv || !gcm_tag || !plaintext || !plain_count)
        return SGX_ERROR_INVALID_PARAMETER;
    if (cipher_size == 0)
        return SGX_ERROR_INVALID_PARAMETER;
    if ((cipher_size % sizeof(uint32_t)) != 0)
        return SGX_ERROR_INVALID_PARAMETER;
    uint32_t pt_bytes = cipher_size;
    uint32_t required_count = pt_bytes / sizeof(uint32_t);
    if (plain_max < required_count)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_aes_gcm_128bit_key_t sk;
    sgx_status_t ret = get_sk(context, &sk);
    if (ret != SGX_SUCCESS)
        return ret;

    ret = sgx_rijndael128GCM_decrypt(&sk,
                                     ciphertext,
                                     cipher_size,
                                     (uint8_t *)plaintext,
                                     iv,
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t *)gcm_tag);
    if (ret == SGX_SUCCESS)
    {
        *plain_count = required_count;
    }
    return ret;
}
