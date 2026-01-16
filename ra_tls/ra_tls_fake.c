#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

#include "ra_tls.h"

// Minimal fake RA-TLS: generate self-signed cert with ECDSA P-256 key, no quote.
int ra_tls_create_key_and_crt_der(uint8_t *der_key, size_t *der_key_size,
                                  uint8_t *der_crt, size_t *der_crt_size)
{
    int ret = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context key;
    mbedtls_x509write_cert crt;
    int len = 0;
    size_t crt_old_size = 0;
    size_t key_old_size = 0;
    unsigned char serial_buf[8] = {0x01}; // Serial number = 1 in DER

    const char *pers = "ratls_fake";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&crt);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0)
        goto cleanup;

    // Generate EC key
    if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
        goto cleanup;
    if ((ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
                                   mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        goto cleanup;

    // Self-signed cert
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

    // Set serial number to 1 (required, 0 is invalid)
    mbedtls_x509write_crt_set_serial_raw(&crt, serial_buf, 1);

    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);
    mbedtls_x509write_crt_set_subject_name(&crt, "CN=RATLS-SIM,O=Local,C=NA");
    mbedtls_x509write_crt_set_issuer_name(&crt, "CN=RATLS-SIM,O=Local,C=NA");
    mbedtls_x509write_crt_set_validity(&crt, "20240101000000", "20300101000000");
    mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
    mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                                  MBEDTLS_X509_KU_KEY_AGREEMENT);

    // Write cert to DER
    len = mbedtls_x509write_crt_der(&crt, der_crt, *der_crt_size,
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
    if (len < 0)
    {
        ret = len;
        printf("[RA-TLS] Certificate generation failed: %d\n", ret);
        goto cleanup;
    }
    // mbedtls writes DER at end of buffer - move to start
    crt_old_size = *der_crt_size;
    *der_crt_size = (size_t)len;
    printf("[RA-TLS] Cert DER len=%d, crt_old_size=%zu, moving from offset %zu\n", len, crt_old_size, crt_old_size - len);
    printf("[RA-TLS] First 16 bytes of cert: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           der_crt[crt_old_size - len], der_crt[crt_old_size - len + 1], der_crt[crt_old_size - len + 2], der_crt[crt_old_size - len + 3],
           der_crt[crt_old_size - len + 4], der_crt[crt_old_size - len + 5], der_crt[crt_old_size - len + 6], der_crt[crt_old_size - len + 7],
           der_crt[crt_old_size - len + 8], der_crt[crt_old_size - len + 9], der_crt[crt_old_size - len + 10], der_crt[crt_old_size - len + 11],
           der_crt[crt_old_size - len + 12], der_crt[crt_old_size - len + 13], der_crt[crt_old_size - len + 14], der_crt[crt_old_size - len + 15]);
    memmove(der_crt, der_crt + (crt_old_size - len), len);

    // Write key to DER
    len = mbedtls_pk_write_key_der(&key, der_key, *der_key_size);
    if (len < 0)
    {
        ret = len;
        printf("[RA-TLS] Key generation failed: %d\n", ret);
        goto cleanup;
    }
    // mbedtls writes DER at end of buffer - move to start
    key_old_size = *der_key_size;
    *der_key_size = (size_t)len;
    printf("[RA-TLS] Key DER len=%d, key_old_size=%zu, moving from offset %zu\n", len, key_old_size, key_old_size - len);
    memmove(der_key, der_key + (key_old_size - len), len);

    ret = 0;

cleanup:
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}
