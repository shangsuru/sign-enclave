#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "CommandLineParser.h"

sgx_enclave_id_t global_eid = 0;

int initialize_enclave(void)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    ret_error_support(ret);
    return -1;
  }

  return 0;
}

void ocall_print_string(const char *str)
{
  printf("%s", str);
}

int main(int argc, char **argv)
{
  sgx_status_t ret = SGX_SUCCESS;
  int res = -1;

  CommandLineArguments args = getArgs(argc, argv);

  if (initialize_enclave() < 0)
  {
    printf("Enclave couldn't get initialized ...\n");
    return -1;
  }

  ret = ecdsa_init(global_eid, &res);

  if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
  {
    printf("Failed at ecdsa_init");
  }

  switch (args.status)
  {
  case CommandLineStatus::SIGN:
    std::cout << "Please sign the message " << args.message << std::endl;
    break;
  case CommandLineStatus::VERIFY:
    std::cout << "Please verify message " << args.message << " with signature file " << args.signature_file << std::endl;
    break;
  default:
    std::cout << "An error occured" << std::endl;
  }

  sgx_destroy_enclave(global_eid);

  printf("Info: SignEnclave successfully returned.\n");
  return 0;
}
