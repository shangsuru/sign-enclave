cmake_minimum_required(VERSION 2.8)
project(sign_enclave)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)

set(E_SRCS enclave/Enclave.cpp)


include_directories(${SGX_INCLUDE_DIR} include app enclave)
set(EDL_SEARCH_PATHS enclave)

add_trusted_library(trusted_lib SRCS ${T_SRCS} EDL enclave/Enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
add_enclave_library(enclave SRCS ${E_SRCS} TRUSTED_LIBS trusted_lib EDL enclave/Enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${LDS})
enclave_sign(enclave KEY enclave/Enclave_private_test.pem CONFIG enclave/Enclave.config.xml)

set(SRCS app/App.cpp app/CommandLineParser.cpp app/ErrorSupport.cpp app/FileIO.cpp include/Base64Encoding.cpp)
add_untrusted_executable(sign-enclave SRCS ${SRCS} EDL enclave/Enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
add_dependencies(sign-enclave enclave-sign)
