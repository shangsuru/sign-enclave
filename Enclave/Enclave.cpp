#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <string>
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

uint32_t get_sealed_data_size()
{
  char *encrypt_data = (char *)privateKey.r;
  return sgx_calc_sealed_data_size(NULL, (uint32_t)strlen(encrypt_data));
}

sgx_status_t seal_data(uint8_t *sealed_blob, uint32_t data_size)
{
  char *encrypt_data = (char *)privateKey.r;
  printf("Data to encrypt is: ");
  printf(encrypt_data);
  printf("\n");

  uint32_t sealed_data_size = sgx_calc_sealed_data_size(NULL, (uint32_t)strlen(encrypt_data));
  if (sealed_data_size == UINT32_MAX)
    return SGX_ERROR_UNEXPECTED;
  if (sealed_data_size > data_size)
    return SGX_ERROR_INVALID_PARAMETER;

  uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
  if (temp_sealed_buf == NULL)
    return SGX_ERROR_OUT_OF_MEMORY;
  sgx_status_t err = sgx_seal_data(NULL, NULL, (uint32_t)strlen(encrypt_data), (uint8_t *)encrypt_data, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
  if (err == SGX_SUCCESS)
  {
    // Copy the sealed data to outside buffer
    memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
  }

  free(temp_sealed_buf);
  return err;
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size)
{
  char *encrypt_data = (char *)privateKey.r;
  uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
  if (decrypt_data_len == UINT32_MAX)
    return SGX_ERROR_UNEXPECTED;
  if (decrypt_data_len > data_size)
    return SGX_ERROR_INVALID_PARAMETER;

  uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
  if (decrypt_data == NULL)
  {
    return SGX_ERROR_OUT_OF_MEMORY;
  }

  sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, NULL, NULL, decrypt_data, &decrypt_data_len);
  if (ret != SGX_SUCCESS)
  {
    free(decrypt_data);
    return ret;
  }

  if (memcmp(decrypt_data, encrypt_data, strlen(encrypt_data)))
  {
    ret = SGX_ERROR_UNEXPECTED;
  }

  memcpy(privateKey.r, decrypt_data, sizeof(sgx_ec256_private_t));

  printf("Data that was unsealed is: ");
  printf((char *)decrypt_data);
  printf("\n");
  free(decrypt_data);
  return ret;
}

// Initializes the ECDSA context and creates a new keypair
int ecdsa_init()
{
  sgx_status_t ret = sgx_ecc256_open_context(&context);
  sgx_sealed_data_t *enc_data = NULL;
  SealedData *unsealed_data = NULL;
  size_t enc_data_size;

  if (ret != SGX_SUCCESS)
    goto error;

  /*if (keyfile != NULL)
  {
    printf("Key file was given");
    // Read in keyfile
    ocall_read_data(keyfile, (char **)&enc_data, &enc_data_size);
    uint32_t dec_size = sgx_get_encrypt_txt_len(enc_data);
    if (dec_size != 0)
    {
      unsealed_data = (SealedData *)malloc(dec_size);
      enc_data_size = sgx_calc_sealed_data_size(NULL, sizeof(SealedData{}));
      sgx_sealed_data_t *tmp = (sgx_sealed_data_t *)malloc(enc_data_size);
      memcpy(tmp, enc_data, enc_data_size);
      ret = sgx_unseal_data(tmp, NULL, NULL, (uint8_t *)unsealed_data, &dec_size);
      if (ret != SGX_SUCCESS)
      {
        printf("Failed to unseal data");
        goto error;
      }
      privateKey = unsealed_data->privateKey;
      publicKey = unsealed_data->publicKey;
    }
    else
      printf("Failed to get encrypt txt len");
  }
  else*/
  ret = sgx_ecc256_create_key_pair(&privateKey, &publicKey, context);

error:
  if (unsealed_data != NULL)
  {
    printf("Unsealed data is not null");
    free(unsealed_data);
  }
  return ret;
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