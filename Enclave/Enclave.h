#pragma once

#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <cstring>
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "Base64Encoding.h"

#if defined(__cplusplus)
extern "C"
{
#endif

  int printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif