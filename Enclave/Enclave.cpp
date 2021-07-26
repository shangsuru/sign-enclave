#include "Enclave.h"
#include "Enclave_t.h"

sgx_ecc_state_handle_t context;
sgx_ec256_private_t ec256_private_key;
sgx_ec256_public_t ec256_public_key;
const size_t MAX_MESSAGE_LENGTH = 255;

struct DataToSeal
{
  sgx_ec256_private_t privateKey;
  sgx_ec256_public_t publicKey;
};

uint32_t get_sealed_data_size()
{
  return sgx_calc_sealed_data_size(NULL, sizeof(DataToSeal{}));
}

sgx_status_t seal_data(uint8_t *sealed_blob, uint32_t sealed_size)
{
  sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
  sgx_sealed_data_t *sealed_data = NULL;
  DataToSeal data;
  data.privateKey = ec256_private_key;
  data.publicKey = ec256_public_key;

  if (sealed_size != 0)
  {
    sealed_data = (sgx_sealed_data_t *)malloc(sealed_size);
    ret = sgx_seal_data(NULL, NULL, sizeof(data), (uint8_t *)&data, sealed_size, sealed_data);
    if (ret == SGX_SUCCESS)
      memcpy(sealed_blob, sealed_data, sealed_size);
    else
      free(sealed_data);
  }
  return ret;
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size)
{
  sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
  DataToSeal *unsealed_data = NULL;

  uint32_t dec_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed_blob);
  if (dec_size != 0)
  {
    unsealed_data = (DataToSeal *)malloc(dec_size);
    sgx_sealed_data_t *tmp = (sgx_sealed_data_t *)malloc(data_size);
    memcpy(tmp, sealed_blob, data_size);
    ret = sgx_unseal_data(tmp, NULL, NULL, (uint8_t *)unsealed_data, &dec_size);
    if (ret != SGX_SUCCESS)
      goto error;
    ec256_private_key = unsealed_data->privateKey;
    ec256_public_key = unsealed_data->publicKey;

  error:
    if (unsealed_data != NULL)
      free(unsealed_data);
    return ret;
  }
}

// Initializes the ECDSA context and creates a new keypair
int ecdsa_init()
{
  sgx_status_t ret = sgx_ecc256_open_context(&context);

  if (ret != SGX_SUCCESS)
    return ret;

  return sgx_ecc256_create_key_pair(&ec256_private_key, &ec256_public_key, context);
}

// Signs a given message and returns the signature object
int ecdsa_sign(const char *message, void *signature, size_t sig_len)
{
  return sgx_ecdsa_sign((uint8_t *)message, strnlen(message, MAX_MESSAGE_LENGTH), &ec256_private_key, (sgx_ec256_signature_t *)signature, context);
}

// Verifies a given message with its signature object and returns on success SGX_EC_VALID or on failure SGX_EC_INVALID_SIGNATURE
int ecdsa_verify(const char *message, void *signature, size_t sig_len)
{
  uint8_t res;
  sgx_ec256_signature_t *sig = (sgx_ec256_signature_t *)signature;
  sgx_status_t ret = sgx_ecdsa_verify((uint8_t *)message, strnlen(message, MAX_MESSAGE_LENGTH), &ec256_public_key, sig, &res, context);
  return res;
}

// Closes the ECDSA context
int ecdsa_close()
{
  return sgx_ecc256_close_context(context);
}

// Invokes OCALL to display the enclave buffer to the terminal
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