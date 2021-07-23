#pragma once

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "ErrorSupport.h"
#include "sgx_eid.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"
#define SEALED_DATA_FILE "sealed_data_blob.txt"

extern sgx_enclave_id_t global_eid; /* global enclave id */

#if defined(__cplusplus)
extern "C"
{
#endif

  void edger8r_array_attributes(void);
  void edger8r_type_attributes(void);
  void edger8r_pointer_attributes(void);
  void edger8r_function_attributes(void);

  void ecall_libc_functions(void);
  void ecall_libcxx_functions(void);
  void ecall_thread_functions(void);

#if defined(__cplusplus)
}
#endif
