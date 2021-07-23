#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <stdexcept>

#include <unistd.h>
#include <pwd.h>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "App.h"
#include "Enclave_u.h"
#include "CommandLineParser.h"

#define MAX_PATH FILENAME_MAX

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

std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

bool is_base64(unsigned char c)
{
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const *bytes_to_encode, unsigned int in_len)
{
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--)
  {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3)
    {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (i = 0; (i < 4); i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for (j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while ((i++ < 3))
      ret += '=';
  }

  return ret;
}

std::string base64_decode(std::string const &encoded_string)
{
  size_t in_len = encoded_string.size();
  size_t i = 0;
  size_t j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_]))
  {
    char_array_4[i++] = encoded_string[in_];
    in_++;
    if (i == 4)
    {
      for (i = 0; i < 4; i++)
        char_array_4[i] = static_cast<unsigned char>(base64_chars.find(char_array_4[i]));

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i)
  {
    for (j = i; j < 4; j++)
      char_array_4[j] = 0;

    for (j = 0; j < 4; j++)
      char_array_4[j] = static_cast<unsigned char>(base64_chars.find(char_array_4[j]));

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++)
      ret += char_array_3[j];
  }

  return ret;
}

static size_t get_file_size(const char *filename)
{
  std::ifstream ifs(filename, std::ios::in | std::ios::binary);
  if (!ifs.good())
  {
    std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
    return -1;
  }
  ifs.seekg(0, std::ios::end);
  size_t size = (size_t)ifs.tellg();
  return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  if (!ifs.good())
  {
    std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
    return false;
  }
  ifs.read(reinterpret_cast<char *>(buf), bsize);
  if (ifs.fail())
  {
    std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
    return false;
  }
  return true;
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
  if (filename == NULL || buf == NULL || bsize == 0)
    return false;
  std::ofstream ofs(filename, std::ios::binary | std::ios::out);
  if (!ofs.good())
  {
    std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
    return false;
  }
  ofs.seekp(offset, std::ios::beg);
  ofs.write(reinterpret_cast<const char *>(buf), bsize);
  if (ofs.fail())
  {
    std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
    return false;
  }

  return true;
}

static bool seal_and_save_data()
{
  sgx_status_t ret;
  // Get the sealed data size
  uint32_t sealed_data_size = 0;
  ret = get_sealed_data_size(global_eid, &sealed_data_size);
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
    std::cout << "Out of memory" << std::endl;
    return false;
  }
  sgx_status_t retval;
  ret = seal_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
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
    std::cout << "Failed to save the sealed data blob to \"" << SEALED_DATA_FILE << "\"" << std::endl;
    free(temp_sealed_buf);
    return false;
  }

  free(temp_sealed_buf);

  std::cout << "Sealing data succeeded." << std::endl;
  return true;
}

static bool read_and_unseal_data()
{
  sgx_status_t ret;
  // Read the sealed blob from the file
  size_t fsize = get_file_size(SEALED_DATA_FILE);
  if (fsize == (size_t)-1)
  {
    std::cout << "Failed to get the file size of \"" << SEALED_DATA_FILE << "\"" << std::endl;
    return false;
  }
  uint8_t *temp_buf = (uint8_t *)malloc(fsize);
  if (temp_buf == NULL)
  {
    std::cout << "Out of memory" << std::endl;
    return false;
  }
  if (read_file_to_buf(SEALED_DATA_FILE, temp_buf, fsize) == false)
  {
    std::cout << "Failed to read the sealed data blob from \"" << SEALED_DATA_FILE << "\"" << std::endl;
    free(temp_buf);
    return false;
  }

  // Unseal the sealed blob
  sgx_status_t retval;
  ret = unseal_data(global_eid, &retval, temp_buf, fsize);
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

  std::cout << "Unseal succeeded." << std::endl;
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

  // Enclave_Seal: seal the secret and save the data blob to a file
  if (seal_and_save_data() == false)
  {
    std::cout << "Failed to seal the secret and save it to a file." << std::endl;
    return -1;
  }

  // Enclave_Unseal: read the data blob from the file and unseal it.
  if (read_and_unseal_data() == false)
  {
    std::cout << "Failed to unseal the data blob." << std::endl;
    return -1;
  }

  return 0;

  /*
  ret = ecdsa_init(global_eid, &res, args.import_keyfile);

  if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
    std::cerr << "Failed at ecdsa_init" << std::endl;

  switch (args.command)
  {
  case Command::SIGN:
  {
    sgx_ec256_signature_t sig;
    ret = ecdsa_sign(global_eid, &res, args.message, (void *)&sig, sizeof(sgx_ec256_signature_t));
    if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
    {
      std::cerr << "Failed at ecdsa_sign" << std::endl;
      break;
    }

    std::string signature_str = base64_encode((unsigned char *)&sig, sizeof(sig));
    std::cout << "Signature of message " << args.message << " successfully signed:" << std::endl
              << signature_str << std::endl;

    ret = ecdsa_verify(global_eid, &res, args.message, (void *)(base64_decode(signature_str).c_str()), sizeof(sgx_ec256_signature_t));
    if (ret != SGX_SUCCESS || res != SGX_EC_VALID)
    {
      std::cerr << "[DELETE] Failed at ecdsa_verify" << std::endl;
      break;
    }
    std::cout << "[DELETE] Signature of message " << args.message << " successfully verified!" << std::endl;

    std::cout << strlen(args.message) << " " << signature_str.length() << std::endl;

    break;
  }
  case Command::VERIFY:
    std::cout << strlen(args.message) << " " << args.signature.length() << std::endl;
    ret = ecdsa_verify(global_eid, &res, args.message, (void *)(base64_decode(args.signature).c_str()), sizeof(sgx_ec256_signature_t));
    if (ret != SGX_SUCCESS || res != SGX_EC_VALID)
    {
      std::cerr << "Failed at ecdsa_verify" << std::endl;
      break;
    }
    std::cout << "Signature of message " << args.message << " successfully verified!" << std::endl;
    break;
  default:
    std::cout << "An error occurred" << std::endl;
  }

  if (args.export_keyfile != NULL)
  {
    ret = ecdsa_seal_keys(global_eid, &res, args.export_keyfile);
    if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
      std::cerr << "Failed at ecdsa_seal_keys" << std::endl;
  }
*/
  sgx_destroy_enclave(global_eid);

  std::cout << "Info: SignEnclave successfully returned." << std::endl;
  return 0;
}
