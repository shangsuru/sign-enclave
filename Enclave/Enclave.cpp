#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "sgx_tcrypto.h"

sgx_ecc_state_handle_t context;
sgx_ec256_private_t privateKey;
sgx_ec256_public_t publicKey;

// Initializes the ECDSA context and creates a new keypair
int ecdsa_init()
{
  sgx_status_t ret = sgx_ecc256_open_context(&context);

  if (ret != SGX_SUCCESS)
    return ret;

  return sgx_ecc256_create_key_pair(&privateKey, &publicKey, context);
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