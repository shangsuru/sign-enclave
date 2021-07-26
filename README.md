# SignEnclave

The project demonstrates several fundamental usages of Intel(R) Software Guard 
Extensions (Intel(R) SGX) SDK:
- Initializing and destroying an enclave
- Creating ECALLs or OCALLs
- Using ECDSA from SGXs cryptographic API

## Getting Started
1. Install Intel(R) SGX SDK for Linux OS
2. Make sure your environment is set:
```
source ${sgx-sdk-install-path}/environment
```
3. Build the code
```
cmake -S . -B build
cmake --build build
cd build
```

## Example Usage

```
./sign-enclave -m babel
> Signature of message babel successfully signed:
> FMWMW01Rogkga0GJG6NcUThuH5LUX/Iv7b6eGcHz8fMqK3JQuFGItzILzXFO71MqSQzv3LpgOebGVfO59n3a/A==

./sign-enclave -p babel -s FMWMW01Rogkga0GJG6NcUThuH5LUX/Iv7b6eGcHz8fMqK3JQuFGItzILzXFO71MqSQzv3LpgOebGVfO59n3a/A==
> Signature of message babel successfully verified!
```



