# SignEnclave

The project demonstrates several fundamental usages of Intel(R) Software Guard
Extensions (Intel(R) SGX) SDK:

-   Initializing and destroying an enclave
-   Creating ECALLs or OCALLs
-   Using ECDSA from SGXs cryptographic API

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

## Running with Docker

Alternatively, if your processor does not support SGX, you can easily build and run it inside a Docker container.

1. Install the Remote-Containers extension of VSCode.
2. Reopen the workspace inside the devcontainer
   (command `Remote-Containers: Open folder in container`)

Inside the container, you can build the code in simulation mode:

4. `cmake -DSGX_HW=OFF -DSGX_MODE=Debug -DCMAKE_BUILD_TYPE=Debug -S . -B build`
5. `cd build && make -j 5`

## Example Usage

```
./sign-enclave -m babel
> Signature of message babel successfully signed:
> FMWMW01Rogkga0GJG6NcUThuH5LUX/Iv7b6eGcHz8fMqK3JQuFGItzILzXFO71MqSQzv3LpgOebGVfO59n3a/A==

./sign-enclave -p babel -s FMWMW01Rogkga0GJG6NcUThuH5LUX/Iv7b6eGcHz8fMqK3JQuFGItzILzXFO71MqSQzv3LpgOebGVfO59n3a/A==
> Signature of message babel successfully verified!
```
