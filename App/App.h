#pragma once

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <stdexcept>

#include "ErrorSupport.h"
#include "Enclave_u.h"
#include "CommandLineParser.h"
#include "Base64Encoding.h"
#include "FileIO.h"
#include "sgx_eid.h"
#include <unistd.h>
#include <pwd.h>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"

#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"
#define SEALED_KEY_FILE "sealed_data_blob.txt"
#define MAX_PATH FILENAME_MAX

sgx_enclave_id_t global_eid = 0;

/**
 * Initializes the enclave (in DEBUG mode).
 * 
 * @returns true if successful, else false
 */
bool initialize_enclave();

/**
 * Stores key pair for ECDSA signature inside the sealed key file.
 * 
 * @returns true if successful, else false
 */
bool seal_and_save_keys();

/**
 * Unseals key pair for ECDSA signature from the sealed key file
 * and sets them as the current public and private key.
 * 
 * @returns true, if successful, else false
 */
bool read_and_unseal_keys();
