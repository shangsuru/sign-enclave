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
  CommandLineArguments args = getArgs(argc, argv);

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

  if (initialize_enclave() < 0)
  {
    printf("Enter a character before exit ...\n");
    getchar();
    return -1;
  }

  int r;
  int a = 3;
  int b = 5;

  add(global_eid, &r, &a, &b);

  printf("r = %d\n", r);

  sgx_destroy_enclave(global_eid);

  printf("Info: SampleEnclave successfully returned.\n");

  printf("Enter a character before exit ...\n");
  getchar();
  return 0;
}
