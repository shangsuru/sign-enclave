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

void ocall_write_data(const char *file_name, const char *p_data)
{
  std::ofstream keyfile;
  keyfile.open(file_name);
  keyfile << p_data;
  keyfile.close();
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
  {
    sgx_ec256_signature_t sig;
    ret = ecdsa_sign(global_eid, &res, args.message, (void *)&sig, sizeof(sgx_ec256_signature_t));
    if (ret != SGX_SUCCESS || res != SGX_SUCCESS)
    {
      std::cerr << "Failed at ecdsa_sign" << std::endl;
      break;
    }
    std::cout << "Signature of message " << args.message << " successfully signed!" << std::endl;

    std::string signature_str = base64_encode((unsigned char *)&sig, sizeof(sig));
    std::cout << signature_str << "\n";

    ret = ecdsa_verify(global_eid, &res, args.message, (void *)(base64_decode(signature_str).c_str()), sizeof(sgx_ec256_signature_t));
    if (ret != SGX_SUCCESS || res != SGX_EC_VALID)
    {
      std::cerr << "Failed at ecdsa_verify" << std::endl;
      break;
    }
    std::cout << "Signature of message " << args.message << " successfully verified!" << std::endl;

    break;
  }
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
