#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

sgx_ecc_state_handle_t context;
sgx_ec256_private_t privateKey;
sgx_ec256_public_t publicKey;
const size_t MAX_MESSAGE_LENGTH = 255;

struct SealedData
{
  sgx_ec256_private_t privateKey;
  sgx_ec256_public_t publicKey;
};

// Initializes the ECDSA context and creates a new keypair
int ecdsa_init()
{
  sgx_status_t ret = sgx_ecc256_open_context(&context);

  if (ret != SGX_SUCCESS)
    return ret;

  return sgx_ecc256_create_key_pair(&privateKey, &publicKey, context);
}

// Signs a given message and returns the signature object
int ecdsa_sign(const char *message, void *signature, size_t sig_len)
{
  return sgx_ecdsa_sign((uint8_t *)message, strnlen(message, MAX_MESSAGE_LENGTH), &privateKey, (sgx_ec256_signature_t *)signature, context);
}

// Verifies a given message with its signature object and returns on success SGX_EC_VALID or on failure SGX_EC_INVALID_SIGNATURE
int ecdsa_verify(const char *message, void *signature, size_t sig_len)
{
  uint8_t res;
  sgx_ec256_signature_t *sig = (sgx_ec256_signature_t *)signature;
  sgx_status_t ret = sgx_ecdsa_verify((uint8_t *)message, strnlen(message, MAX_MESSAGE_LENGTH), &publicKey, sig, &res, context);
  return res;
}

// Closes the ECDSA context
int ecdsa_close()
{
  return sgx_ecc256_close_context(context);
}

// Seals the private and public key and writes them to disk
int ecdsa_seal_keys(const char *sealed_data_file)
{
  sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
  SealedData data{privateKey, publicKey};
  size_t dataSize = sizeof(data);
  uint32_t sealedSize = sgx_calc_sealed_data_size(NULL, dataSize);
  if (sealedSize != 0)
  {
    sgx_sealed_data_t *sealedData = (sgx_sealed_data_t *)malloc(sealedSize);
    ret = sgx_seal_data(NULL, NULL, dataSize, (uint8_t *)&data, sealedSize, sealedData);
    if (ret == SGX_SUCCESS)
      ocall_write_data(sealed_data_file, (char *)sealedData);
    else
      free(sealedData);
  }
  return ret;
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