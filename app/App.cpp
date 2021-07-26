#include "App.h"

bool initialize_enclave()
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    ret_error_support(ret);
    return false;
  }
  return true;
}

bool seal_and_save_keys()
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
  if (write_buf_to_file(SEALED_KEY_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
  {
    std::cerr << "Failed to save the sealed data blob to \"" << SEALED_KEY_FILE << "\"" << std::endl;
    free(temp_sealed_buf);
    return false;
  }

  free(temp_sealed_buf);
  return true;
}

bool read_and_unseal_keys()
{
  sgx_status_t ret;
  // Read the sealed blob from the file
  size_t fsize = get_file_size(SEALED_KEY_FILE);
  if (fsize == (size_t)-1)
  {
    return false;
  }
  uint8_t *temp_buf = (uint8_t *)malloc(fsize);
  if (temp_buf == NULL)
  {
    std::cerr << "Out of memory" << std::endl;
    return false;
  }
  if (read_file_to_buf(SEALED_KEY_FILE, temp_buf, fsize) == false)
  {
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

  if (initialize_enclave() == false)
  {
    std::cerr << "Enclave couldn't get initialized ..." << std::endl;
    return -1;
  }

  // Generate new keys if reset option was set or there was an error reading the keys from sealed storage
  if (args.reset || read_and_unseal_keys() == false)
    generate_key_pair(global_eid, &res);

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
