#include "Enclave.h"
#include "Enclave_t.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_utils.h"
#include "sgx_tcrypto.h"

/* Stan PSI dla wielu klientow */
static uint32_t client1_set[10] = {0};
static uint32_t client1_size = 0;
static uint32_t client2_set[10] = {0};
static uint32_t client2_size = 0;
static uint32_t clients_registered = 0;

/* Stan ECDH per klient */
static sgx_ecc_state_handle_t g_ecc_ctx[2] = {0, 0};
static sgx_ec256_private_t g_srv_priv[2];
static sgx_ec256_public_t g_srv_pub[2];
static sgx_aes_gcm_128bit_key_t g_kx_keys[2];
static int g_kx_ready[2] = {0, 0};

/* Publiczny klucz SP - na sztywno do RA */
static const sgx_ec256_public_t g_sp_pub_key = {
    {0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
     0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
     0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
     0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38},
    {0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
     0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
     0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
     0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06}};

/* Owijka printf do OCALL */
int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

/* Funkcje Remote Attestation */

sgx_status_t enclave_init_ra(int b_pse, sgx_ra_context_t *p_context)
{
    sgx_status_t ret;
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
    printf("[ENCLAVE] RA initialized, context: %u\n", *p_context);
    return ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    printf("[ENCLAVE] RA context closed: %u\n", context);
    return ret;
}

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t *p_message,
                                   size_t message_size,
                                   uint8_t *p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if (mac_size != sizeof(sgx_mac_t))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (message_size > UINT32_MAX)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
    if (SGX_SUCCESS != ret)
    {
        return ret;
    }

    sgx_mac_t mac;
    ret = sgx_rijndael128_cmac_msg(&mk_key,
                                   p_message,
                                   (uint32_t)message_size,
                                   &mac);
    if (SGX_SUCCESS != ret)
    {
        return ret;
    }

    if (0 == consttime_memequal(p_mac, mac, sizeof(mac)))
    {
        return SGX_ERROR_MAC_MISMATCH;
    }

    printf("[ENCLAVE] Attestation result MAC verified\n");
    return SGX_SUCCESS;
}

sgx_status_t get_enclave_report(const sgx_target_info_t *target_info,
                                sgx_report_t *report)
{
    sgx_report_data_t report_data = {0};
    sgx_status_t ret = sgx_create_report(target_info, &report_data, report);
    printf("[ENCLAVE] Created report\n");
    return ret;
}

/* Pobranie klucza SK z RA */
static sgx_status_t get_sk_key(sgx_ra_context_t context, sgx_ec_key_128bit_t *sk_key)
{
    if (!sk_key)
        return SGX_ERROR_INVALID_PARAMETER;
    return sgx_ra_get_keys(context, SGX_RA_KEY_SK, sk_key);
}

/* Pobierz klucz sesyjny (SK) z kontekstu RA */
sgx_status_t get_session_key(sgx_ra_context_t context, uint8_t *sk_key)
{
    if (!sk_key)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_ec_key_128bit_t key;
    sgx_status_t ret = get_sk_key(context, &key);
    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] Failed to get SK key: 0x%x\n", ret);
        return ret;
    }

    memcpy(sk_key, &key, 16);
    printf("[ENCLAVE] Session key retrieved\n");
    return SGX_SUCCESS;
}

/* Szyfruj wynik PSI AES-GCM uzywajac klucza SK */
sgx_status_t encrypt_psi_result(sgx_ra_context_t context,
                                const uint32_t *result,
                                uint32_t result_count,
                                uint8_t *encrypted_data,
                                uint32_t encrypted_size,
                                uint8_t *gcm_mac)
{
    if (!result || !encrypted_data || !gcm_mac)
        return SGX_ERROR_INVALID_PARAMETER;

    if (encrypted_size < result_count * sizeof(uint32_t))
        return SGX_ERROR_INVALID_PARAMETER;

    /* Pobierz klucz SK z RA (dziala w SIM/HW) */
    sgx_ec_key_128bit_t sk_key;
    sgx_status_t ret = get_sk_key(context, &sk_key);
    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] Failed to get SK key for encryption: 0x%x\n", ret);
        return ret;
    }

    /* IV zerowy do dema; w produkcji losowy */
    uint8_t aes_gcm_iv[12] = {0};

    /* Szyfrowanie AES-GCM */
    ret = sgx_rijndael128GCM_encrypt(&sk_key,
                                     (const uint8_t *)result,
                                     result_count * sizeof(uint32_t),
                                     encrypted_data,
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     (sgx_aes_gcm_128bit_tag_t *)gcm_mac);

    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] AES-GCM encryption failed: 0x%x\n", ret);
        return ret;
    }

    printf("[ENCLAVE] PSI result encrypted (%u bytes)\n", result_count * sizeof(uint32_t));
    return SGX_SUCCESS;
}

/* Odszyfruj dane klienta AES-GCM kluczem SK */
sgx_status_t decrypt_client_data(sgx_ra_context_t context,
                                 const uint8_t *encrypted_data,
                                 uint32_t encrypted_size,
                                 const uint8_t *gcm_mac,
                                 uint32_t *decrypted_set,
                                 uint32_t *set_size)
{
    if (!encrypted_data || !gcm_mac || !decrypted_set || !set_size)
        return SGX_ERROR_INVALID_PARAMETER;

    /* Pobierz klucz SK z RA */
    sgx_ec_key_128bit_t sk_key;
    sgx_status_t ret = get_sk_key(context, &sk_key);
    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] Failed to get SK key for decryption: 0x%x\n", ret);
        return ret;
    }

    /* IV zerowy (musi zgadzac sie z szyfrowaniem) */
    uint8_t aes_gcm_iv[12] = {0};

    /* Odszyfrowanie AES-GCM */
    ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                     encrypted_data,
                                     encrypted_size,
                                     (uint8_t *)decrypted_set,
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t *)gcm_mac);

    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] AES-GCM decryption failed: 0x%x\n", ret);
        return ret;
    }

    *set_size = encrypted_size / sizeof(uint32_t);
    printf("[ENCLAVE] Client data decrypted (%u elements)\n", *set_size);
    return SGX_SUCCESS;
}

/* KX: inicjalizacja po stronie serwera - generuj efemeryczna pare i zwroc pubkey */
sgx_status_t kx_server_init(uint32_t client_id, uint8_t *server_pubkey)
{
    if (client_id < 1 || client_id > 2 || !server_pubkey)
        return SGX_ERROR_INVALID_PARAMETER;
    uint32_t idx = client_id - 1;
    sgx_status_t ret = sgx_ecc256_open_context(&g_ecc_ctx[idx]);
    if (ret != SGX_SUCCESS)
        return ret;
    ret = sgx_ecc256_create_key_pair(&g_srv_priv[idx], &g_srv_pub[idx], g_ecc_ctx[idx]);
    if (ret != SGX_SUCCESS)
        return ret;
    /* serialize pubkey (X||Y) */
    memcpy(server_pubkey, g_srv_pub[idx].gx, 32);
    memcpy(server_pubkey + 32, g_srv_pub[idx].gy, 32);
    return SGX_SUCCESS;
}

/* KX: zakonczenie po stronie serwera - policz sekret DH i wyprowadz AES-128 */
sgx_status_t kx_server_finish(uint32_t client_id, const uint8_t *client_pubkey, sgx_status_t *enclave_ret)
{
    if (client_id < 1 || client_id > 2 || !client_pubkey || !enclave_ret)
        return SGX_ERROR_INVALID_PARAMETER;
    uint32_t idx = client_id - 1;
    sgx_ec256_public_t peer{};
    memcpy(peer.gx, client_pubkey, 32);
    memcpy(peer.gy, client_pubkey + 32, 32);
    sgx_ec256_dh_shared_t shared{};
    sgx_status_t ret = sgx_ecc256_compute_shared_dhkey(&g_srv_priv[idx], &peer, &shared, g_ecc_ctx[idx]);
    if (ret != SGX_SUCCESS)
    {
        *enclave_ret = ret;
        return SGX_SUCCESS;
    }

    // Log shared secret for debugging
    printf("[ENCLAVE] kx_server_finish: Shared secret first 16 bytes: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", ((uint8_t *)&shared)[i]);
    }
    printf("\n");

    /* Derive AES-128 from shared (use SHA256, take first 16 bytes) */
    sgx_sha256_hash_t hash;
    ret = sgx_sha256_msg((const uint8_t *)&shared, sizeof(shared), &hash);
    if (ret != SGX_SUCCESS)
    {
        *enclave_ret = ret;
        return SGX_SUCCESS;
    }

    // Log derived key for debugging
    printf("[ENCLAVE] kx_server_finish: Derived AES key (16 bytes): ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");

    memcpy(&g_kx_keys[idx], hash, 16);
    g_kx_ready[idx] = 1;
    *enclave_ret = SGX_SUCCESS;
    return SGX_SUCCESS;
}

static sgx_status_t kx_get_key(uint32_t client_id, sgx_aes_gcm_128bit_key_t *key)
{
    if (client_id < 1 || client_id > 2 || !key)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t idx = client_id - 1;
    if (!g_kx_ready[idx])
        return SGX_ERROR_INVALID_STATE;

    // Log the key being used
    printf("[ENCLAVE] kx_get_key: Using AES key: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", ((uint8_t *)&g_kx_keys[idx])[i]);
    }
    printf("\n");

    memcpy(key, &g_kx_keys[idx], sizeof(*key));
    return SGX_SUCCESS;
}

sgx_status_t kx_encrypt_server(uint32_t client_id,
                               const uint32_t *plaintext,
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
    sgx_status_t ret = kx_get_key(client_id, &key);
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

sgx_status_t kx_decrypt_server(uint32_t client_id,
                               const uint8_t *ciphertext,
                               uint32_t cipher_size,
                               const uint8_t *iv,
                               const uint8_t *gcm_tag,
                               uint32_t *plaintext,
                               uint32_t plain_max,
                               uint32_t *plain_count)
{
    printf("[ENCLAVE] kx_decrypt_server called: client_id=%u cipher_size=%u plain_max=%u\n",
           client_id, cipher_size, plain_max);

    if (!ciphertext || !iv || !gcm_tag || !plaintext || !plain_count)
    {
        printf("[ENCLAVE] kx_decrypt_server: Invalid parameters (nullptrs)\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (cipher_size % sizeof(uint32_t))
    {
        printf("[ENCLAVE] kx_decrypt_server: cipher_size not multiple of uint32_t\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t pt_bytes = cipher_size;
    uint32_t required = pt_bytes / sizeof(uint32_t);
    if (plain_max < required)
    {
        printf("[ENCLAVE] kx_decrypt_server: plain_max (%u) < required (%u)\n", plain_max, required);
        return SGX_ERROR_INVALID_PARAMETER;
    }
    sgx_aes_gcm_128bit_key_t key;
    sgx_status_t ret = kx_get_key(client_id, &key);
    if (ret != SGX_SUCCESS)
    {
        printf("[ENCLAVE] kx_decrypt_server: kx_get_key failed: 0x%x\n", ret);
        return ret;
    }

    printf("[ENCLAVE] kx_decrypt_server: Calling sgx_rijndael128GCM_decrypt...\n");
    ret = sgx_rijndael128GCM_decrypt(&key,
                                     ciphertext,
                                     cipher_size,
                                     (uint8_t *)plaintext,
                                     iv,
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t *)gcm_tag);

    printf("[ENCLAVE] kx_decrypt_server: sgx_rijndael128GCM_decrypt returned: 0x%x\n", ret);
    if (ret == SGX_SUCCESS)
    {
        *plain_count = required;
        printf("[ENCLAVE] kx_decrypt_server: Decryption successful, count=%u\n", required);
    }
    else
    {
        printf("[ENCLAVE] kx_decrypt_server: Decryption FAILED with 0x%x\n", ret);
    }
    return ret;
}

/* Rejestracja zbioru klienta */
sgx_status_t ecall_register_client_set(uint32_t client_id, const uint32_t *set, uint32_t set_size)
{
    if (!set || set_size == 0 || set_size > 10)
        return SGX_ERROR_INVALID_PARAMETER;

    if (client_id == 1)
    {
        memcpy(client1_set, set, set_size * sizeof(uint32_t));
        client1_size = set_size;
        printf("[ENCLAVE] Client 1 registered set of size %u\n", set_size);
        clients_registered |= 0x1; // Mark client 1 as registered
    }
    else if (client_id == 2)
    {
        memcpy(client2_set, set, set_size * sizeof(uint32_t));
        client2_size = set_size;
        printf("[ENCLAVE] Client 2 registered set of size %u\n", set_size);
        clients_registered |= 0x2; // Mark client 2 as registered
    }
    else
        return SGX_ERROR_INVALID_PARAMETER;

    return SGX_SUCCESS;
}

/* Oblicz czesc wspolna PSI */
sgx_status_t ecall_compute_psi_multi(uint32_t *result, uint32_t *result_count)
{
    if (!result || !result_count || (clients_registered & 0x3) != 0x3)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t count = 0;

    for (uint32_t i = 0; i < client1_size && count < 10; i++)
    {
        for (uint32_t j = 0; j < client2_size; j++)
        {
            if (client1_set[i] == client2_set[j])
            {
                result[count++] = client1_set[i];
                break;
            }
        }
    }

    *result_count = count;
    printf("[ENCLAVE] Multi-client PSI: intersection size = %u\n", count);
    return SGX_SUCCESS;
}

/* Single-client PSI mode */
sgx_status_t ecall_compute_psi_count(
    const uint32_t *set1,
    const uint32_t *set2,
    uint32_t *result,
    uint32_t *result_count)
{
    if (!set1 || !set2 || !result || !result_count)
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t count = 0;

    for (int i = 0; i < 5; i++)
    {
        for (int j = 0; j < 5; j++)
        {
            if (set1[i] == set2[j])
            {
                result[count++] = set1[i];
                break;
            }
        }
    }

    *result_count = count;
    printf("[ENCLAVE] PSI computed: intersection size = %u\n", count);
    return SGX_SUCCESS;
}

/* Simple echo function for testing - returns input unchanged */
sgx_status_t ecall_echo(uint32_t client_id,
                        const uint8_t *input_data,
                        uint32_t input_size,
                        uint8_t *output_data,
                        uint32_t *output_size)
{
    if (input_size > 1024)
        return SGX_ERROR_INVALID_PARAMETER;

    memcpy(output_data, input_data, input_size);
    *output_size = input_size;

    printf("[ENCLAVE] Echo: client %u sent %u bytes, returned %u bytes\n",
           client_id, input_size, input_size);
    return SGX_SUCCESS;
}