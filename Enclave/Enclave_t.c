#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_enclave_init_ra(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_ra_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_init_ra_t* ms = SGX_CAST(ms_enclave_init_ra_t*, pms);
	ms_enclave_init_ra_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclave_init_ra_t), ms, sizeof(ms_enclave_init_ra_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = __in_ms.ms_p_context;
	size_t _len_p_context = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_p_context = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_context != NULL && _len_p_context != 0) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}
	_in_retval = enclave_init_ra(__in_ms.ms_b_pse, _in_p_context);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_context) {
		if (memcpy_verw_s(_tmp_p_context, _len_p_context, _in_p_context, _len_p_context)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_context) free(_in_p_context);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_close_t* ms = SGX_CAST(ms_enclave_ra_close_t*, pms);
	ms_enclave_ra_close_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_enclave_ra_close_t), ms, sizeof(ms_enclave_ra_close_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t _in_retval;


	_in_retval = enclave_ra_close(__in_ms.ms_context);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_verify_att_result_mac(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_verify_att_result_mac_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_verify_att_result_mac_t* ms = SGX_CAST(ms_verify_att_result_mac_t*, pms);
	ms_verify_att_result_mac_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_verify_att_result_mac_t), ms, sizeof(ms_verify_att_result_mac_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_message = __in_ms.ms_message;
	size_t _tmp_message_size = __in_ms.ms_message_size;
	size_t _len_message = _tmp_message_size;
	uint8_t* _in_message = NULL;
	uint8_t* _tmp_mac = __in_ms.ms_mac;
	size_t _tmp_mac_size = __in_ms.ms_mac_size;
	size_t _len_mac = _tmp_mac_size;
	uint8_t* _in_mac = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		if ( _len_message % sizeof(*_tmp_message) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_message = (uint8_t*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		if ( _len_mac % sizeof(*_tmp_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_mac, _len_mac, _tmp_mac, _len_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = verify_att_result_mac(__in_ms.ms_context, _in_message, _tmp_message_size, _in_mac, _tmp_mac_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_message) free(_in_message);
	if (_in_mac) free(_in_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_enclave_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_enclave_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_enclave_report_t* ms = SGX_CAST(ms_get_enclave_report_t*, pms);
	ms_get_enclave_report_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_get_enclave_report_t), ms, sizeof(ms_get_enclave_report_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_target_info_t* _tmp_target_info = __in_ms.ms_target_info;
	size_t _len_target_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_target_info = NULL;
	sgx_report_t* _tmp_report = __in_ms.ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);
	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_target_info != NULL && _len_target_info != 0) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info, _len_target_info, _tmp_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	_in_retval = get_enclave_report((const sgx_target_info_t*)_in_target_info, _in_report);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_report) {
		if (memcpy_verw_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_target_info) free(_in_target_info);
	if (_in_report) free(_in_report);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_session_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_session_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_session_key_t* ms = SGX_CAST(ms_get_session_key_t*, pms);
	ms_get_session_key_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_get_session_key_t), ms, sizeof(ms_get_session_key_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sk_key = __in_ms.ms_sk_key;
	size_t _len_sk_key = 16;
	uint8_t* _in_sk_key = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sk_key, _len_sk_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sk_key != NULL && _len_sk_key != 0) {
		if ( _len_sk_key % sizeof(*_tmp_sk_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sk_key = (uint8_t*)malloc(_len_sk_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sk_key, 0, _len_sk_key);
	}
	_in_retval = get_session_key(__in_ms.ms_context, _in_sk_key);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_sk_key) {
		if (memcpy_verw_s(_tmp_sk_key, _len_sk_key, _in_sk_key, _len_sk_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sk_key) free(_in_sk_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_encrypt_psi_result(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encrypt_psi_result_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encrypt_psi_result_t* ms = SGX_CAST(ms_encrypt_psi_result_t*, pms);
	ms_encrypt_psi_result_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_encrypt_psi_result_t), ms, sizeof(ms_encrypt_psi_result_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint32_t* _tmp_result = __in_ms.ms_result;
	uint32_t _tmp_result_count = __in_ms.ms_result_count;
	size_t _len_result = _tmp_result_count * sizeof(uint32_t);
	uint32_t* _in_result = NULL;
	uint8_t* _tmp_encrypted_data = __in_ms.ms_encrypted_data;
	uint32_t _tmp_encrypted_size = __in_ms.ms_encrypted_size;
	size_t _len_encrypted_data = _tmp_encrypted_size;
	uint8_t* _in_encrypted_data = NULL;
	uint8_t* _tmp_gcm_mac = __in_ms.ms_gcm_mac;
	size_t _len_gcm_mac = 16;
	uint8_t* _in_gcm_mac = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_result) != 0 &&
		(size_t)_tmp_result_count > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_data, _len_encrypted_data);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac, _len_gcm_mac);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_result = (uint32_t*)malloc(_len_result);
		if (_in_result == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_result, _len_result, _tmp_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_encrypted_data != NULL && _len_encrypted_data != 0) {
		if ( _len_encrypted_data % sizeof(*_tmp_encrypted_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_data = (uint8_t*)malloc(_len_encrypted_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_data, 0, _len_encrypted_data);
	}
	if (_tmp_gcm_mac != NULL && _len_gcm_mac != 0) {
		if ( _len_gcm_mac % sizeof(*_tmp_gcm_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_gcm_mac = (uint8_t*)malloc(_len_gcm_mac)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_gcm_mac, 0, _len_gcm_mac);
	}
	_in_retval = encrypt_psi_result(__in_ms.ms_context, (const uint32_t*)_in_result, _tmp_result_count, _in_encrypted_data, _tmp_encrypted_size, _in_gcm_mac);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_encrypted_data) {
		if (memcpy_verw_s(_tmp_encrypted_data, _len_encrypted_data, _in_encrypted_data, _len_encrypted_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_gcm_mac) {
		if (memcpy_verw_s(_tmp_gcm_mac, _len_gcm_mac, _in_gcm_mac, _len_gcm_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_result) free(_in_result);
	if (_in_encrypted_data) free(_in_encrypted_data);
	if (_in_gcm_mac) free(_in_gcm_mac);
	return status;
}

static sgx_status_t SGX_CDECL sgx_decrypt_client_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_decrypt_client_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_decrypt_client_data_t* ms = SGX_CAST(ms_decrypt_client_data_t*, pms);
	ms_decrypt_client_data_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_decrypt_client_data_t), ms, sizeof(ms_decrypt_client_data_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_encrypted_data = __in_ms.ms_encrypted_data;
	uint32_t _tmp_encrypted_size = __in_ms.ms_encrypted_size;
	size_t _len_encrypted_data = _tmp_encrypted_size;
	uint8_t* _in_encrypted_data = NULL;
	const uint8_t* _tmp_gcm_mac = __in_ms.ms_gcm_mac;
	size_t _len_gcm_mac = 16;
	uint8_t* _in_gcm_mac = NULL;
	uint32_t* _tmp_decrypted_set = __in_ms.ms_decrypted_set;
	size_t _len_decrypted_set = 10 * sizeof(uint32_t);
	uint32_t* _in_decrypted_set = NULL;
	uint32_t* _tmp_set_size = __in_ms.ms_set_size;
	size_t _len_set_size = sizeof(uint32_t);
	uint32_t* _in_set_size = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_decrypted_set) != 0 &&
		10 > (SIZE_MAX / sizeof(*_tmp_decrypted_set))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_encrypted_data, _len_encrypted_data);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac, _len_gcm_mac);
	CHECK_UNIQUE_POINTER(_tmp_decrypted_set, _len_decrypted_set);
	CHECK_UNIQUE_POINTER(_tmp_set_size, _len_set_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_data != NULL && _len_encrypted_data != 0) {
		if ( _len_encrypted_data % sizeof(*_tmp_encrypted_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_encrypted_data = (uint8_t*)malloc(_len_encrypted_data);
		if (_in_encrypted_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encrypted_data, _len_encrypted_data, _tmp_encrypted_data, _len_encrypted_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_gcm_mac != NULL && _len_gcm_mac != 0) {
		if ( _len_gcm_mac % sizeof(*_tmp_gcm_mac) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_gcm_mac = (uint8_t*)malloc(_len_gcm_mac);
		if (_in_gcm_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_gcm_mac, _len_gcm_mac, _tmp_gcm_mac, _len_gcm_mac)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_decrypted_set != NULL && _len_decrypted_set != 0) {
		if ( _len_decrypted_set % sizeof(*_tmp_decrypted_set) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_decrypted_set = (uint32_t*)malloc(_len_decrypted_set)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_decrypted_set, 0, _len_decrypted_set);
	}
	if (_tmp_set_size != NULL && _len_set_size != 0) {
		if ( _len_set_size % sizeof(*_tmp_set_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_set_size = (uint32_t*)malloc(_len_set_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_set_size, 0, _len_set_size);
	}
	_in_retval = decrypt_client_data(__in_ms.ms_context, (const uint8_t*)_in_encrypted_data, _tmp_encrypted_size, (const uint8_t*)_in_gcm_mac, _in_decrypted_set, _in_set_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_decrypted_set) {
		if (memcpy_verw_s(_tmp_decrypted_set, _len_decrypted_set, _in_decrypted_set, _len_decrypted_set)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_set_size) {
		if (memcpy_verw_s(_tmp_set_size, _len_set_size, _in_set_size, _len_set_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_encrypted_data) free(_in_encrypted_data);
	if (_in_gcm_mac) free(_in_gcm_mac);
	if (_in_decrypted_set) free(_in_decrypted_set);
	if (_in_set_size) free(_in_set_size);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_compute_psi_count(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_compute_psi_count_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_compute_psi_count_t* ms = SGX_CAST(ms_ecall_compute_psi_count_t*, pms);
	ms_ecall_compute_psi_count_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_compute_psi_count_t), ms, sizeof(ms_ecall_compute_psi_count_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint32_t* _tmp_set1 = __in_ms.ms_set1;
	size_t _len_set1 = 5 * sizeof(uint32_t);
	uint32_t* _in_set1 = NULL;
	const uint32_t* _tmp_set2 = __in_ms.ms_set2;
	size_t _len_set2 = 5 * sizeof(uint32_t);
	uint32_t* _in_set2 = NULL;
	uint32_t* _tmp_result = __in_ms.ms_result;
	size_t _len_result = 5 * sizeof(uint32_t);
	uint32_t* _in_result = NULL;
	uint32_t* _tmp_result_count = __in_ms.ms_result_count;
	size_t _len_result_count = sizeof(uint32_t);
	uint32_t* _in_result_count = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_set1) != 0 &&
		5 > (SIZE_MAX / sizeof(*_tmp_set1))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_set2) != 0 &&
		5 > (SIZE_MAX / sizeof(*_tmp_set2))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_result) != 0 &&
		5 > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_set1, _len_set1);
	CHECK_UNIQUE_POINTER(_tmp_set2, _len_set2);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);
	CHECK_UNIQUE_POINTER(_tmp_result_count, _len_result_count);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_set1 != NULL && _len_set1 != 0) {
		if ( _len_set1 % sizeof(*_tmp_set1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_set1 = (uint32_t*)malloc(_len_set1);
		if (_in_set1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_set1, _len_set1, _tmp_set1, _len_set1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_set2 != NULL && _len_set2 != 0) {
		if ( _len_set2 % sizeof(*_tmp_set2) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_set2 = (uint32_t*)malloc(_len_set2);
		if (_in_set2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_set2, _len_set2, _tmp_set2, _len_set2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint32_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	if (_tmp_result_count != NULL && _len_result_count != 0) {
		if ( _len_result_count % sizeof(*_tmp_result_count) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result_count = (uint32_t*)malloc(_len_result_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result_count, 0, _len_result_count);
	}
	_in_retval = ecall_compute_psi_count((const uint32_t*)_in_set1, (const uint32_t*)_in_set2, _in_result, _in_result_count);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_result_count) {
		if (memcpy_verw_s(_tmp_result_count, _len_result_count, _in_result_count, _len_result_count)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_set1) free(_in_set1);
	if (_in_set2) free(_in_set2);
	if (_in_result) free(_in_result);
	if (_in_result_count) free(_in_result_count);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_register_client_set(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_register_client_set_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_register_client_set_t* ms = SGX_CAST(ms_ecall_register_client_set_t*, pms);
	ms_ecall_register_client_set_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_register_client_set_t), ms, sizeof(ms_ecall_register_client_set_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint32_t* _tmp_set = __in_ms.ms_set;
	size_t _len_set = 10 * sizeof(uint32_t);
	uint32_t* _in_set = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_set) != 0 &&
		10 > (SIZE_MAX / sizeof(*_tmp_set))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_set, _len_set);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_set != NULL && _len_set != 0) {
		if ( _len_set % sizeof(*_tmp_set) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_set = (uint32_t*)malloc(_len_set);
		if (_in_set == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_set, _len_set, _tmp_set, _len_set)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_register_client_set(__in_ms.ms_client_id, (const uint32_t*)_in_set, __in_ms.ms_set_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_set) free(_in_set);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_compute_psi_multi(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_compute_psi_multi_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_compute_psi_multi_t* ms = SGX_CAST(ms_ecall_compute_psi_multi_t*, pms);
	ms_ecall_compute_psi_multi_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_compute_psi_multi_t), ms, sizeof(ms_ecall_compute_psi_multi_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint32_t* _tmp_result = __in_ms.ms_result;
	size_t _len_result = 10 * sizeof(uint32_t);
	uint32_t* _in_result = NULL;
	uint32_t* _tmp_result_count = __in_ms.ms_result_count;
	size_t _len_result_count = sizeof(uint32_t);
	uint32_t* _in_result_count = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_result) != 0 &&
		10 > (SIZE_MAX / sizeof(*_tmp_result))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);
	CHECK_UNIQUE_POINTER(_tmp_result_count, _len_result_count);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (uint32_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	if (_tmp_result_count != NULL && _len_result_count != 0) {
		if ( _len_result_count % sizeof(*_tmp_result_count) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result_count = (uint32_t*)malloc(_len_result_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result_count, 0, _len_result_count);
	}
	_in_retval = ecall_compute_psi_multi(_in_result, _in_result_count);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_result_count) {
		if (memcpy_verw_s(_tmp_result_count, _len_result_count, _in_result_count, _len_result_count)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_result) free(_in_result);
	if (_in_result_count) free(_in_result_count);
	return status;
}

static sgx_status_t SGX_CDECL sgx_kx_server_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_kx_server_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_kx_server_init_t* ms = SGX_CAST(ms_kx_server_init_t*, pms);
	ms_kx_server_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_kx_server_init_t), ms, sizeof(ms_kx_server_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_server_pubkey = __in_ms.ms_server_pubkey;
	size_t _len_server_pubkey = 64;
	uint8_t* _in_server_pubkey = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_server_pubkey, _len_server_pubkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_server_pubkey != NULL && _len_server_pubkey != 0) {
		if ( _len_server_pubkey % sizeof(*_tmp_server_pubkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_server_pubkey = (uint8_t*)malloc(_len_server_pubkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_server_pubkey, 0, _len_server_pubkey);
	}
	_in_retval = kx_server_init(__in_ms.ms_client_id, _in_server_pubkey);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_server_pubkey) {
		if (memcpy_verw_s(_tmp_server_pubkey, _len_server_pubkey, _in_server_pubkey, _len_server_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_server_pubkey) free(_in_server_pubkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_kx_server_finish(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_kx_server_finish_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_kx_server_finish_t* ms = SGX_CAST(ms_kx_server_finish_t*, pms);
	ms_kx_server_finish_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_kx_server_finish_t), ms, sizeof(ms_kx_server_finish_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_client_pubkey = __in_ms.ms_client_pubkey;
	size_t _len_client_pubkey = 64;
	uint8_t* _in_client_pubkey = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_client_pubkey, _len_client_pubkey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_client_pubkey != NULL && _len_client_pubkey != 0) {
		if ( _len_client_pubkey % sizeof(*_tmp_client_pubkey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_client_pubkey = (uint8_t*)malloc(_len_client_pubkey);
		if (_in_client_pubkey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_client_pubkey, _len_client_pubkey, _tmp_client_pubkey, _len_client_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = kx_server_finish(__in_ms.ms_client_id, (const uint8_t*)_in_client_pubkey);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_client_pubkey) free(_in_client_pubkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_kx_encrypt_server(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_kx_encrypt_server_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_kx_encrypt_server_t* ms = SGX_CAST(ms_kx_encrypt_server_t*, pms);
	ms_kx_encrypt_server_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_kx_encrypt_server_t), ms, sizeof(ms_kx_encrypt_server_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint32_t* _tmp_plaintext = __in_ms.ms_plaintext;
	uint32_t _tmp_plain_count = __in_ms.ms_plain_count;
	size_t _len_plaintext = _tmp_plain_count * sizeof(uint32_t);
	uint32_t* _in_plaintext = NULL;
	const uint8_t* _tmp_iv = __in_ms.ms_iv;
	size_t _len_iv = 12;
	uint8_t* _in_iv = NULL;
	uint8_t* _tmp_ciphertext = __in_ms.ms_ciphertext;
	uint32_t _tmp_cipher_size = __in_ms.ms_cipher_size;
	size_t _len_ciphertext = _tmp_cipher_size;
	uint8_t* _in_ciphertext = NULL;
	uint8_t* _tmp_gcm_tag = __in_ms.ms_gcm_tag;
	size_t _len_gcm_tag = 16;
	uint8_t* _in_gcm_tag = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_plaintext) != 0 &&
		(size_t)_tmp_plain_count > (SIZE_MAX / sizeof(*_tmp_plaintext))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_gcm_tag, _len_gcm_tag);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_plaintext = (uint32_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plaintext, _len_plaintext, _tmp_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		if ( _len_iv % sizeof(*_tmp_iv) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iv, _len_iv, _tmp_iv, _len_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ciphertext = (uint8_t*)malloc(_len_ciphertext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ciphertext, 0, _len_ciphertext);
	}
	if (_tmp_gcm_tag != NULL && _len_gcm_tag != 0) {
		if ( _len_gcm_tag % sizeof(*_tmp_gcm_tag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_gcm_tag = (uint8_t*)malloc(_len_gcm_tag)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_gcm_tag, 0, _len_gcm_tag);
	}
	_in_retval = kx_encrypt_server(__in_ms.ms_client_id, (const uint32_t*)_in_plaintext, _tmp_plain_count, (const uint8_t*)_in_iv, _in_ciphertext, _tmp_cipher_size, _in_gcm_tag);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_ciphertext) {
		if (memcpy_verw_s(_tmp_ciphertext, _len_ciphertext, _in_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_gcm_tag) {
		if (memcpy_verw_s(_tmp_gcm_tag, _len_gcm_tag, _in_gcm_tag, _len_gcm_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_iv) free(_in_iv);
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_gcm_tag) free(_in_gcm_tag);
	return status;
}

static sgx_status_t SGX_CDECL sgx_kx_decrypt_server(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_kx_decrypt_server_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_kx_decrypt_server_t* ms = SGX_CAST(ms_kx_decrypt_server_t*, pms);
	ms_kx_decrypt_server_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_kx_decrypt_server_t), ms, sizeof(ms_kx_decrypt_server_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_ciphertext = __in_ms.ms_ciphertext;
	uint32_t _tmp_cipher_size = __in_ms.ms_cipher_size;
	size_t _len_ciphertext = _tmp_cipher_size;
	uint8_t* _in_ciphertext = NULL;
	const uint8_t* _tmp_iv = __in_ms.ms_iv;
	size_t _len_iv = 12;
	uint8_t* _in_iv = NULL;
	const uint8_t* _tmp_gcm_tag = __in_ms.ms_gcm_tag;
	size_t _len_gcm_tag = 16;
	uint8_t* _in_gcm_tag = NULL;
	uint32_t* _tmp_plaintext = __in_ms.ms_plaintext;
	uint32_t _tmp_plain_max = __in_ms.ms_plain_max;
	size_t _len_plaintext = _tmp_plain_max * sizeof(uint32_t);
	uint32_t* _in_plaintext = NULL;
	uint32_t* _tmp_plain_count = __in_ms.ms_plain_count;
	size_t _len_plain_count = sizeof(uint32_t);
	uint32_t* _in_plain_count = NULL;
	sgx_status_t _in_retval;

	if (sizeof(*_tmp_plaintext) != 0 &&
		(size_t)_tmp_plain_max > (SIZE_MAX / sizeof(*_tmp_plaintext))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_ciphertext, _len_ciphertext);
	CHECK_UNIQUE_POINTER(_tmp_iv, _len_iv);
	CHECK_UNIQUE_POINTER(_tmp_gcm_tag, _len_gcm_tag);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_plain_count, _len_plain_count);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ciphertext != NULL && _len_ciphertext != 0) {
		if ( _len_ciphertext % sizeof(*_tmp_ciphertext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ciphertext = (uint8_t*)malloc(_len_ciphertext);
		if (_in_ciphertext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ciphertext, _len_ciphertext, _tmp_ciphertext, _len_ciphertext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_iv != NULL && _len_iv != 0) {
		if ( _len_iv % sizeof(*_tmp_iv) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_iv = (uint8_t*)malloc(_len_iv);
		if (_in_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iv, _len_iv, _tmp_iv, _len_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_gcm_tag != NULL && _len_gcm_tag != 0) {
		if ( _len_gcm_tag % sizeof(*_tmp_gcm_tag) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_gcm_tag = (uint8_t*)malloc(_len_gcm_tag);
		if (_in_gcm_tag == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_gcm_tag, _len_gcm_tag, _tmp_gcm_tag, _len_gcm_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_plaintext = (uint32_t*)malloc(_len_plaintext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plaintext, 0, _len_plaintext);
	}
	if (_tmp_plain_count != NULL && _len_plain_count != 0) {
		if ( _len_plain_count % sizeof(*_tmp_plain_count) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_plain_count = (uint32_t*)malloc(_len_plain_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plain_count, 0, _len_plain_count);
	}
	_in_retval = kx_decrypt_server(__in_ms.ms_client_id, (const uint8_t*)_in_ciphertext, _tmp_cipher_size, (const uint8_t*)_in_iv, (const uint8_t*)_in_gcm_tag, _in_plaintext, _tmp_plain_max, _in_plain_count);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_plaintext) {
		if (memcpy_verw_s(_tmp_plaintext, _len_plaintext, _in_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_plain_count) {
		if (memcpy_verw_s(_tmp_plain_count, _len_plain_count, _in_plain_count, _len_plain_count)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ciphertext) free(_in_ciphertext);
	if (_in_iv) free(_in_iv);
	if (_in_gcm_tag) free(_in_gcm_tag);
	if (_in_plaintext) free(_in_plaintext);
	if (_in_plain_count) free(_in_plain_count);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	ms_sgx_ra_get_ga_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_ra_get_ga_t), ms, sizeof(ms_sgx_ra_get_ga_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = __in_ms.ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	_in_retval = sgx_ra_get_ga(__in_ms.ms_context, _in_g_a);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_g_a) {
		if (memcpy_verw_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_g_a) free(_in_g_a);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	ms_sgx_ra_proc_msg2_trusted_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_ra_proc_msg2_trusted_t), ms, sizeof(ms_sgx_ra_proc_msg2_trusted_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = __in_ms.ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = __in_ms.ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = __in_ms.ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = __in_ms.ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	_in_retval = sgx_ra_proc_msg2_trusted(__in_ms.ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_p_report) {
		if (memcpy_verw_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p_nonce) {
		if (memcpy_verw_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_msg2) free(_in_p_msg2);
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) free(_in_p_report);
	if (_in_p_nonce) free(_in_p_nonce);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	ms_sgx_ra_get_msg3_trusted_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_sgx_ra_get_msg3_trusted_t), ms, sizeof(ms_sgx_ra_get_msg3_trusted_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = __in_ms.ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = __in_ms.ms_p_msg3;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = sgx_ra_get_msg3_trusted(__in_ms.ms_context, __in_ms.ms_quote_size, _in_qe_report, _tmp_p_msg3, __in_ms.ms_msg3_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_qe_report) free(_in_qe_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[17];
} g_ecall_table = {
	17,
	{
		{(void*)(uintptr_t)sgx_enclave_init_ra, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_close, 0, 0},
		{(void*)(uintptr_t)sgx_verify_att_result_mac, 0, 0},
		{(void*)(uintptr_t)sgx_get_enclave_report, 0, 0},
		{(void*)(uintptr_t)sgx_get_session_key, 0, 0},
		{(void*)(uintptr_t)sgx_encrypt_psi_result, 0, 0},
		{(void*)(uintptr_t)sgx_decrypt_client_data, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_compute_psi_count, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_register_client_set, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_compute_psi_multi, 0, 0},
		{(void*)(uintptr_t)sgx_kx_server_init, 0, 0},
		{(void*)(uintptr_t)sgx_kx_server_finish, 0, 0},
		{(void*)(uintptr_t)sgx_kx_encrypt_server, 0, 0},
		{(void*)(uintptr_t)sgx_kx_decrypt_server, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][17];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

