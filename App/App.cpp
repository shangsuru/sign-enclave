#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <stdexcept>

#include <unistd.h>
#include <pwd.h>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "App.h"
#include "Enclave_u.h"

#define MAX_PATH FILENAME_MAX

sgx_enclave_id_t global_eid = 0;

int initialize_enclave()
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

static bool seal_and_save_keys()
{
  uint32_t sealed_data_size = 0;
  sgx_status_t ret = get_sealed_data_size(global_eid, &sealed_data_size);

  if (ret != SGX_SUCCESS)
  {
    ret_error_support(ret);
    return false;
  }
  else if (sealed_data_size == UINT32_MAX)
  {
    return false;
  }

  uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
  if (temp_sealed_buf == NULL)
  {
    std::cerr << "Out of memory" << std::endl;
    return false;
  }

  sgx_status_t retval;
  ret = seal_keys(global_eid, &retval, temp_sealed_buf, sealed_data_size);
  if (ret != SGX_SUCCESS)
  {
    ret_error_support(ret);
    free(temp_sealed_buf);
    return false;
  }
  else if (retval != SGX_SUCCESS)
  {
    ret_error_support(retval);
    free(temp_sealed_buf);
    return false;
  }

  // Save the sealed blob
  if (write_buf_to_file(SEALED_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
  {
    std::cerr << "Failed to save the sealed data blob to \"" << SEALED_DATA_FILE << "\"" << std::endl;
    free(temp_sealed_buf);
    return false;
  }

  free(temp_sealed_buf);
  return true;
}

static bool read_and_unseal_keys()
{
  sgx_status_t ret;
  // Read the sealed blob from the file
  size_t fsize = get_file_size(SEALED_DATA_FILE);
  if (fsize == (size_t)-1)
  {
    std::cerr << "Failed to get the file size of \"" << SEALED_DATA_FILE << "\"" << std::endl;
    return false;
  }
  uint8_t *temp_buf = (uint8_t *)malloc(fsize);
  if (temp_buf == NULL)
  {
    std::cerr << "Out of memory" << std::endl;
    return false;
  }
  if (read_file_to_buf(SEALED_DATA_FILE, temp_buf, fsize) == false)
  {
    std::cerr << "Failed to read the sealed data blob from \"" << SEALED_DATA_FILE << "\"" << std::endl;
    free(temp_buf);
    return false;
  }

  // Unseal the sealed blob
  sgx_status_t retval;
  ret = unseal_keys(global_eid, &retval, temp_buf, fsize);
  if (ret != SGX_SUCCESS)
  {
    ret_error_support(ret);
    free(temp_buf);
    return false;
  }
  else if (retval != SGX_SUCCESS)
  {
    ret_error_support(retval);
    free(temp_buf);
    return false;
  }

  free(temp_buf);
  return true;
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

  if (args.reset)
    generate_key_pair(global_eid, &res);
  else
    read_and_unseal_keys();

  switch (args.command)
  {
  case Command::SIGN:
  {
    sgx_ec256_signature_t sig;
    ret = sign(global_eid, &res, args.message, (void *)&sig, sizeof(sgx_ec256_signature_t));
    if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
    {
      std::cerr << "Failed at sign" << std::endl;
      break;
    }

    std::string signature_str = base64_encode((unsigned char *)&sig, sizeof(sig));
    std::cout << "Signature of message " << args.message << " successfully signed:" << std::endl
              << signature_str << std::endl;

    break;
  }
  case Command::VERIFY:
    ret = verify(global_eid, &res, args.message, (void *)(base64_decode(args.signature).c_str()), sizeof(sgx_ec256_signature_t));
    if (ret != SGX_SUCCESS || res != SGX_EC_VALID)
    {
      std::cerr << "Failed at verify" << std::endl;
      break;
    }
    std::cout << "Signature of message " << args.message << " successfully verified!" << std::endl;
    break;
  default:
    return -1;
  }

  if (seal_and_save_keys() == false)
  {
    std::cout << "Failed to seal the secret and save it to a file." << std::endl;
    return -1;
  }

  sgx_destroy_enclave(global_eid);
  return 0;
}
