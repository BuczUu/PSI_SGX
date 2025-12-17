#include "Enclave_u.h"
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

typedef struct ms_get_enclave_report_t {
	sgx_status_t ms_retval;
	const sgx_target_info_t* ms_target_info;
	sgx_report_t* ms_report;
} ms_get_enclave_report_t;

typedef struct ms_get_session_key_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_sk_key;
} ms_get_session_key_t;

typedef struct ms_encrypt_psi_result_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const uint32_t* ms_result;
	uint32_t ms_result_count;
	uint8_t* ms_encrypted_data;
	uint32_t ms_encrypted_size;
	uint8_t* ms_gcm_mac;
} ms_encrypt_psi_result_t;

typedef struct ms_decrypt_client_data_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const uint8_t* ms_encrypted_data;
	uint32_t ms_encrypted_size;
	const uint8_t* ms_gcm_mac;
	uint32_t* ms_decrypted_set;
	uint32_t* ms_set_size;
} ms_decrypt_client_data_t;

typedef struct ms_ecall_compute_psi_count_t {
	sgx_status_t ms_retval;
	const uint32_t* ms_set1;
	const uint32_t* ms_set2;
	uint32_t* ms_result;
	uint32_t* ms_result_count;
} ms_ecall_compute_psi_count_t;

typedef struct ms_ecall_register_client_set_t {
	sgx_status_t ms_retval;
	uint32_t ms_client_id;
	const uint32_t* ms_set;
	uint32_t ms_set_size;
} ms_ecall_register_client_set_t;

typedef struct ms_ecall_compute_psi_multi_t {
	sgx_status_t ms_retval;
	uint32_t* ms_result;
	uint32_t* ms_result_count;
} ms_ecall_compute_psi_multi_t;

typedef struct ms_kx_server_init_t {
	sgx_status_t ms_retval;
	uint32_t ms_client_id;
	uint8_t* ms_server_pubkey;
} ms_kx_server_init_t;

typedef struct ms_kx_server_finish_t {
	sgx_status_t ms_retval;
	uint32_t ms_client_id;
	const uint8_t* ms_client_pubkey;
} ms_kx_server_finish_t;

typedef struct ms_kx_encrypt_server_t {
	sgx_status_t ms_retval;
	uint32_t ms_client_id;
	const uint32_t* ms_plaintext;
	uint32_t ms_plain_count;
	const uint8_t* ms_iv;
	uint8_t* ms_ciphertext;
	uint32_t ms_cipher_size;
	uint8_t* ms_gcm_tag;
} ms_kx_encrypt_server_t;

typedef struct ms_kx_decrypt_server_t {
	sgx_status_t ms_retval;
	uint32_t ms_client_id;
	const uint8_t* ms_ciphertext;
	uint32_t ms_cipher_size;
	const uint8_t* ms_iv;
	const uint8_t* ms_gcm_tag;
	uint32_t* ms_plaintext;
	uint32_t ms_plain_max;
	uint32_t* ms_plain_count;
} ms_kx_decrypt_server_t;

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

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t enclave_init_ra(sgx_enclave_id_t eid, sgx_status_t* retval, int b_pse, sgx_ra_context_t* p_context)
{
	sgx_status_t status;
	ms_enclave_init_ra_t ms;
	ms.ms_b_pse = b_pse;
	ms.ms_p_context = p_context;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_ra_close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context)
{
	sgx_status_t status;
	ms_enclave_ra_close_t ms;
	ms.ms_context = context;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
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
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_enclave_report(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_target_info_t* target_info, sgx_report_t* report)
{
	sgx_status_t status;
	ms_get_enclave_report_t ms;
	ms.ms_target_info = target_info;
	ms.ms_report = report;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_session_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint8_t* sk_key)
{
	sgx_status_t status;
	ms_get_session_key_t ms;
	ms.ms_context = context;
	ms.ms_sk_key = sk_key;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t encrypt_psi_result(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const uint32_t* result, uint32_t result_count, uint8_t* encrypted_data, uint32_t encrypted_size, uint8_t* gcm_mac)
{
	sgx_status_t status;
	ms_encrypt_psi_result_t ms;
	ms.ms_context = context;
	ms.ms_result = result;
	ms.ms_result_count = result_count;
	ms.ms_encrypted_data = encrypted_data;
	ms.ms_encrypted_size = encrypted_size;
	ms.ms_gcm_mac = gcm_mac;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t decrypt_client_data(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const uint8_t* encrypted_data, uint32_t encrypted_size, const uint8_t* gcm_mac, uint32_t* decrypted_set, uint32_t* set_size)
{
	sgx_status_t status;
	ms_decrypt_client_data_t ms;
	ms.ms_context = context;
	ms.ms_encrypted_data = encrypted_data;
	ms.ms_encrypted_size = encrypted_size;
	ms.ms_gcm_mac = gcm_mac;
	ms.ms_decrypted_set = decrypted_set;
	ms.ms_set_size = set_size;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_compute_psi_count(sgx_enclave_id_t eid, sgx_status_t* retval, const uint32_t* set1, const uint32_t* set2, uint32_t* result, uint32_t* result_count)
{
	sgx_status_t status;
	ms_ecall_compute_psi_count_t ms;
	ms.ms_set1 = set1;
	ms.ms_set2 = set2;
	ms.ms_result = result;
	ms.ms_result_count = result_count;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_register_client_set(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, const uint32_t* set, uint32_t set_size)
{
	sgx_status_t status;
	ms_ecall_register_client_set_t ms;
	ms.ms_client_id = client_id;
	ms.ms_set = set;
	ms.ms_set_size = set_size;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_compute_psi_multi(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t* result, uint32_t* result_count)
{
	sgx_status_t status;
	ms_ecall_compute_psi_multi_t ms;
	ms.ms_result = result;
	ms.ms_result_count = result_count;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t kx_server_init(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, uint8_t* server_pubkey)
{
	sgx_status_t status;
	ms_kx_server_init_t ms;
	ms.ms_client_id = client_id;
	ms.ms_server_pubkey = server_pubkey;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t kx_server_finish(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, const uint8_t* client_pubkey)
{
	sgx_status_t status;
	ms_kx_server_finish_t ms;
	ms.ms_client_id = client_id;
	ms.ms_client_pubkey = client_pubkey;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t kx_encrypt_server(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, const uint32_t* plaintext, uint32_t plain_count, const uint8_t* iv, uint8_t* ciphertext, uint32_t cipher_size, uint8_t* gcm_tag)
{
	sgx_status_t status;
	ms_kx_encrypt_server_t ms;
	ms.ms_client_id = client_id;
	ms.ms_plaintext = plaintext;
	ms.ms_plain_count = plain_count;
	ms.ms_iv = iv;
	ms.ms_ciphertext = ciphertext;
	ms.ms_cipher_size = cipher_size;
	ms.ms_gcm_tag = gcm_tag;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t kx_decrypt_server(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t client_id, const uint8_t* ciphertext, uint32_t cipher_size, const uint8_t* iv, const uint8_t* gcm_tag, uint32_t* plaintext, uint32_t plain_max, uint32_t* plain_count)
{
	sgx_status_t status;
	ms_kx_decrypt_server_t ms;
	ms.ms_client_id = client_id;
	ms.ms_ciphertext = ciphertext;
	ms.ms_cipher_size = cipher_size;
	ms.ms_iv = iv;
	ms.ms_gcm_tag = gcm_tag;
	ms.ms_plaintext = plaintext;
	ms.ms_plain_max = plain_max;
	ms.ms_plain_count = plain_count;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
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
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
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
	status = sgx_ecall(eid, 16, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

