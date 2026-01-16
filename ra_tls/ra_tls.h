#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Fake RA-TLS generator for SIM/testing: produces self-signed cert+key (no quote)
    int ra_tls_create_key_and_crt_der(uint8_t *der_key, size_t *der_key_size,
                                      uint8_t *der_crt, size_t *der_crt_size);

#ifdef __cplusplus
}
#endif
