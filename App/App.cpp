#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <fstream>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "sgx_tcrypto.h"
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

void ocall_write_data(const char *file_name, const char *p_data, size_t len)
{
  std::ofstream keyfile;
  keyfile.open(file_name);
  keyfile << p_data;
  keyfile.close();
}

int main(int argc, char **argv)
{
  sgx_status_t ret = SGX_SUCCESS;
  int res = -1;

  CommandLineArguments args = getArgs(argc, argv);

  if (initialize_enclave() < 0)
  {
    std::cerr << "Enclave couldn't get initialized ..." << std::endl;
    return -1;
  }

  ret = ecdsa_init(global_eid, &res);

  if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
    std::cerr << "Failed at ecdsa_init" << std::endl;

  switch (args.command)
  {
  case Command::SIGN:
    sgx_ec256_signature_t sig;
    ret = ecdsa_sign(global_eid, &res, args.message, (void *)&sig, sizeof(sgx_ec256_signature_t));
    if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
    {
      std::cerr << "Failed at ecdsa_sign" << std::endl;
      break;
    }
    std::cout << "Signature of message " << args.message << " successfully signed!" << std::endl;

    ret = ecdsa_verify(global_eid, &res, args.message, (void *)&sig, sizeof(sgx_ec256_signature_t));
    if (ret != SGX_SUCCESS || res != SGX_EC_VALID)
    {
      std::cerr << "Failed at ecdsa_verify" << std::endl;
      break;
    }
    std::cout << "Signature of message " << args.message << " successfully verified!" << std::endl;

    break;
  case Command::VERIFY:
    std::cout << "Verifying the message " << args.message << " with signature file " << args.signature_file << std::endl;
    break;
  default:
    std::cout << "An error occurred" << std::endl;
  }

  if (args.export_key_file != NULL)
  {
    ret = ecdsa_seal_keys(global_eid, &res, args.export_key_file);
    if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
      std::cerr << "Failed at ecdsa_seal_keys" << std::endl;
  }

  sgx_destroy_enclave(global_eid);

  std::cout << "Info: SignEnclave successfully returned." << std::endl;
  return 0;
}
