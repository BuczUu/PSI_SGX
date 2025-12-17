#include "EnclaveClient_t.h"

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

static sgx_status_t SGX_CDECL sgx_verify_server_mrenclave(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_verify_server_mrenclave_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_verify_server_mrenclave_t* ms = SGX_CAST(ms_verify_server_mrenclave_t*, pms);
	ms_verify_server_mrenclave_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_verify_server_mrenclave_t), ms, sizeof(ms_verify_server_mrenclave_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_received_mrenclave = __in_ms.ms_received_mrenclave;
	size_t _len_received_mrenclave = 32;
	uint8_t* _in_received_mrenclave = NULL;
	uint8_t* _tmp_expected_mrenclave = __in_ms.ms_expected_mrenclave;
	size_t _len_expected_mrenclave = 32;
	uint8_t* _in_expected_mrenclave = NULL;
	int* _tmp_match = __in_ms.ms_match;
	size_t _len_match = sizeof(int);
	int* _in_match = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_received_mrenclave, _len_received_mrenclave);
	CHECK_UNIQUE_POINTER(_tmp_expected_mrenclave, _len_expected_mrenclave);
	CHECK_UNIQUE_POINTER(_tmp_match, _len_match);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_received_mrenclave != NULL && _len_received_mrenclave != 0) {
		if ( _len_received_mrenclave % sizeof(*_tmp_received_mrenclave) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_received_mrenclave = (uint8_t*)malloc(_len_received_mrenclave);
		if (_in_received_mrenclave == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_received_mrenclave, _len_received_mrenclave, _tmp_received_mrenclave, _len_received_mrenclave)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_expected_mrenclave != NULL && _len_expected_mrenclave != 0) {
		if ( _len_expected_mrenclave % sizeof(*_tmp_expected_mrenclave) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_expected_mrenclave = (uint8_t*)malloc(_len_expected_mrenclave);
		if (_in_expected_mrenclave == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_expected_mrenclave, _len_expected_mrenclave, _tmp_expected_mrenclave, _len_expected_mrenclave)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_match != NULL && _len_match != 0) {
		if ( _len_match % sizeof(*_tmp_match) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_match = (int*)malloc(_len_match)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_match, 0, _len_match);
	}
	_in_retval = verify_server_mrenclave(__in_ms.ms_context, _in_received_mrenclave, _in_expected_mrenclave, _in_match);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_match) {
		if (memcpy_verw_s(_tmp_match, _len_match, _in_match, _len_match)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_received_mrenclave) free(_in_received_mrenclave);
	if (_in_expected_mrenclave) free(_in_expected_mrenclave);
	if (_in_match) free(_in_match);
	return status;
}

static sgx_status_t SGX_CDECL sgx_kx_client_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_kx_client_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_kx_client_init_t* ms = SGX_CAST(ms_kx_client_init_t*, pms);
	ms_kx_client_init_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_kx_client_init_t), ms, sizeof(ms_kx_client_init_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_client_pubkey = __in_ms.ms_client_pubkey;
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
		if ((_in_client_pubkey = (uint8_t*)malloc(_len_client_pubkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_client_pubkey, 0, _len_client_pubkey);
	}
	_in_retval = kx_client_init(_in_client_pubkey);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_client_pubkey) {
		if (memcpy_verw_s(_tmp_client_pubkey, _len_client_pubkey, _in_client_pubkey, _len_client_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_client_pubkey) free(_in_client_pubkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_kx_client_finish(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_kx_client_finish_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_kx_client_finish_t* ms = SGX_CAST(ms_kx_client_finish_t*, pms);
	ms_kx_client_finish_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_kx_client_finish_t), ms, sizeof(ms_kx_client_finish_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_server_pubkey = __in_ms.ms_server_pubkey;
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
		_in_server_pubkey = (uint8_t*)malloc(_len_server_pubkey);
		if (_in_server_pubkey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_server_pubkey, _len_server_pubkey, _tmp_server_pubkey, _len_server_pubkey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = kx_client_finish((const uint8_t*)_in_server_pubkey);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_server_pubkey) free(_in_server_pubkey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_kx_encrypt_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_kx_encrypt_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_kx_encrypt_client_t* ms = SGX_CAST(ms_kx_encrypt_client_t*, pms);
	ms_kx_encrypt_client_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_kx_encrypt_client_t), ms, sizeof(ms_kx_encrypt_client_t))) {
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
	_in_retval = kx_encrypt_client((const uint32_t*)_in_plaintext, _tmp_plain_count, (const uint8_t*)_in_iv, _in_ciphertext, _tmp_cipher_size, _in_gcm_tag);
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

static sgx_status_t SGX_CDECL sgx_kx_decrypt_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_kx_decrypt_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_kx_decrypt_client_t* ms = SGX_CAST(ms_kx_decrypt_client_t*, pms);
	ms_kx_decrypt_client_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_kx_decrypt_client_t), ms, sizeof(ms_kx_decrypt_client_t))) {
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
	_in_retval = kx_decrypt_client((const uint8_t*)_in_ciphertext, _tmp_cipher_size, (const uint8_t*)_in_iv, (const uint8_t*)_in_gcm_tag, _in_plaintext, _tmp_plain_max, _in_plain_count);
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

static sgx_status_t SGX_CDECL sgx_ecall_ra_encrypt_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ra_encrypt_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_ra_encrypt_client_t* ms = SGX_CAST(ms_ecall_ra_encrypt_client_t*, pms);
	ms_ecall_ra_encrypt_client_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_ra_encrypt_client_t), ms, sizeof(ms_ecall_ra_encrypt_client_t))) {
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
	_in_retval = ecall_ra_encrypt_client(__in_ms.ms_context, (const uint32_t*)_in_plaintext, _tmp_plain_count, (const uint8_t*)_in_iv, _in_ciphertext, _tmp_cipher_size, _in_gcm_tag);
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

static sgx_status_t SGX_CDECL sgx_ecall_ra_decrypt_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ra_decrypt_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_ra_decrypt_client_t* ms = SGX_CAST(ms_ecall_ra_decrypt_client_t*, pms);
	ms_ecall_ra_decrypt_client_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_ra_decrypt_client_t), ms, sizeof(ms_ecall_ra_decrypt_client_t))) {
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
	_in_retval = ecall_ra_decrypt_client(__in_ms.ms_context, (const uint8_t*)_in_ciphertext, _tmp_cipher_size, (const uint8_t*)_in_iv, (const uint8_t*)_in_gcm_tag, _in_plaintext, _tmp_plain_max, _in_plain_count);
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
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[13];
} g_ecall_table = {
	13,
	{
		{(void*)(uintptr_t)sgx_enclave_init_ra, 0, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_close, 0, 0},
		{(void*)(uintptr_t)sgx_verify_att_result_mac, 0, 0},
		{(void*)(uintptr_t)sgx_verify_server_mrenclave, 0, 0},
		{(void*)(uintptr_t)sgx_kx_client_init, 0, 0},
		{(void*)(uintptr_t)sgx_kx_client_finish, 0, 0},
		{(void*)(uintptr_t)sgx_kx_encrypt_client, 0, 0},
		{(void*)(uintptr_t)sgx_kx_decrypt_client, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_ra_encrypt_client, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_ra_decrypt_client, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


