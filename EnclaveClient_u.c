#include "EnclaveClient_u.h"
#include <errno.h>

typedef struct ms_enclave_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_enclave_init_ra_t;

typedef struct ms_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_enclave_ra_close_t;

typedef struct ms_verify_att_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_verify_att_result_mac_t;

typedef struct ms_verify_server_mrenclave_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_received_mrenclave;
	uint8_t* ms_expected_mrenclave;
	int* ms_match;
} ms_verify_server_mrenclave_t;

typedef struct ms_kx_client_init_t {
	sgx_status_t ms_retval;
	uint8_t* ms_client_pubkey;
} ms_kx_client_init_t;

typedef struct ms_kx_client_finish_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_server_pubkey;
} ms_kx_client_finish_t;

typedef struct ms_kx_encrypt_client_t {
	sgx_status_t ms_retval;
	const uint32_t* ms_plaintext;
	uint32_t ms_plain_count;
	const uint8_t* ms_iv;
	uint8_t* ms_ciphertext;
	uint32_t ms_cipher_size;
	uint8_t* ms_gcm_tag;
} ms_kx_encrypt_client_t;

typedef struct ms_kx_decrypt_client_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_ciphertext;
	uint32_t ms_cipher_size;
	const uint8_t* ms_iv;
	const uint8_t* ms_gcm_tag;
	uint32_t* ms_plaintext;
	uint32_t ms_plain_max;
	uint32_t* ms_plain_count;
} ms_kx_decrypt_client_t;

typedef struct ms_ecall_ra_encrypt_client_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const uint32_t* ms_plaintext;
	uint32_t ms_plain_count;
	const uint8_t* ms_iv;
	uint8_t* ms_ciphertext;
	uint32_t ms_cipher_size;
	uint8_t* ms_gcm_tag;
} ms_ecall_ra_encrypt_client_t;

typedef struct ms_ecall_ra_decrypt_client_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const uint8_t* ms_ciphertext;
	uint32_t ms_cipher_size;
	const uint8_t* ms_iv;
	const uint8_t* ms_gcm_tag;
	uint32_t* ms_plaintext;
	uint32_t ms_plain_max;
	uint32_t* ms_plain_count;
} ms_ecall_ra_decrypt_client_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_EnclaveClient = {
	0,
	{ NULL },
};
sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_enclave_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 0, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_enclave_ra_close_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 1, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_att_result_mac(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* message, size_t message_size, uint8_t* mac, size_t mac_size)
{
	sgx_status_t status;
	ms_verify_att_result_mac_t ms;
	ms.ms_context = context;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_mac = mac;
	ms.ms_mac_size = mac_size;
	status = sgx_ecall(eid, 2, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_server_mrenclave(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* received_mrenclave, uint8_t* expected_mrenclave, int* match)
{
	sgx_status_t status;
	ms_verify_server_mrenclave_t ms;
	ms.ms_context = context;
	ms.ms_received_mrenclave = received_mrenclave;
	ms.ms_expected_mrenclave = expected_mrenclave;
	ms.ms_match = match;
	status = sgx_ecall(eid, 3, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t kx_client_init(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* client_pubkey)
{
	sgx_status_t status;
	ms_kx_client_init_t ms;
	ms.ms_client_pubkey = client_pubkey;
	status = sgx_ecall(eid, 4, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t kx_client_finish(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* server_pubkey)
{
	sgx_status_t status;
	ms_kx_client_finish_t ms;
	ms.ms_server_pubkey = server_pubkey;
	status = sgx_ecall(eid, 5, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t kx_encrypt_client(sgx_enclave_id_t eid, sgx_status_t* retval, const uint32_t* plaintext, uint32_t plain_count, const uint8_t* iv, uint8_t* ciphertext, uint32_t cipher_size, uint8_t* gcm_tag)
{
	sgx_status_t status;
	ms_kx_encrypt_client_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_plain_count = plain_count;
	ms.ms_iv = iv;
	ms.ms_ciphertext = ciphertext;
	ms.ms_cipher_size = cipher_size;
	ms.ms_gcm_tag = gcm_tag;
	status = sgx_ecall(eid, 6, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t kx_decrypt_client(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* ciphertext, uint32_t cipher_size, const uint8_t* iv, const uint8_t* gcm_tag, uint32_t* plaintext, uint32_t plain_max, uint32_t* plain_count)
{
	sgx_status_t status;
	ms_kx_decrypt_client_t ms;
	ms.ms_ciphertext = ciphertext;
	ms.ms_cipher_size = cipher_size;
	ms.ms_iv = iv;
	ms.ms_gcm_tag = gcm_tag;
	ms.ms_plaintext = plaintext;
	ms.ms_plain_max = plain_max;
	ms.ms_plain_count = plain_count;
	status = sgx_ecall(eid, 7, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_ra_encrypt_client(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const uint32_t* plaintext, uint32_t plain_count, const uint8_t* iv, uint8_t* ciphertext, uint32_t cipher_size, uint8_t* gcm_tag)
{
	sgx_status_t status;
	ms_ecall_ra_encrypt_client_t ms;
	ms.ms_context = context;
	ms.ms_plaintext = plaintext;
	ms.ms_plain_count = plain_count;
	ms.ms_iv = iv;
	ms.ms_ciphertext = ciphertext;
	ms.ms_cipher_size = cipher_size;
	ms.ms_gcm_tag = gcm_tag;
	status = sgx_ecall(eid, 8, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_ra_decrypt_client(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const uint8_t* ciphertext, uint32_t cipher_size, const uint8_t* iv, const uint8_t* gcm_tag, uint32_t* plaintext, uint32_t plain_max, uint32_t* plain_count)
{
	sgx_status_t status;
	ms_ecall_ra_decrypt_client_t ms;
	ms.ms_context = context;
	ms.ms_ciphertext = ciphertext;
	ms.ms_cipher_size = cipher_size;
	ms.ms_iv = iv;
	ms.ms_gcm_tag = gcm_tag;
	ms.ms_plaintext = plaintext;
	ms.ms_plain_max = plain_max;
	ms.ms_plain_count = plain_count;
	status = sgx_ecall(eid, 9, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 10, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 11, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 12, &ocall_table_EnclaveClient, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

