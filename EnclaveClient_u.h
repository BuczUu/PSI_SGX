#ifndef ENCLAVECLIENT_U_H__
#define ENCLAVECLIENT_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context);
sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context);
sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size);
sgx_status_t verify_server_mrenclave(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* received_mrenclave, uint8_t* expected_mrenclave, int* match);
sgx_status_t kx_client_init(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* client_pubkey);
sgx_status_t kx_client_finish(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* server_pubkey);
sgx_status_t kx_encrypt_client(sgx_enclave_id_t eid, sgx_status_t* retval, const uint32_t* plaintext, uint32_t plain_count, const uint8_t* iv, uint8_t* ciphertext, uint32_t cipher_size, uint8_t* gcm_tag);
sgx_status_t kx_decrypt_client(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* ciphertext, uint32_t cipher_size, const uint8_t* iv, const uint8_t* gcm_tag, uint32_t* plaintext, uint32_t plain_max, uint32_t* plain_count);
sgx_status_t ecall_ra_encrypt_client(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const uint32_t* plaintext, uint32_t plain_count, const uint8_t* iv, uint8_t* ciphertext, uint32_t cipher_size, uint8_t* gcm_tag);
sgx_status_t ecall_ra_decrypt_client(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const uint8_t* ciphertext, uint32_t cipher_size, const uint8_t* iv, const uint8_t* gcm_tag, uint32_t* plaintext, uint32_t plain_max, uint32_t* plain_count);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
