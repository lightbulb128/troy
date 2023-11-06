#pragma once

#include <stdexcept>
#include <iostream>

inline void printCudaError(cudaError_t status, const char* prompt, int line, const char* file) {
    if (status != cudaSuccess) {
        std::cerr << "CUDA error at " << file << ":" << line << 
        "- (prompt='" << prompt << "', status=" << status << ") " << cudaGetErrorString(status) << std::endl;
        if (status != cudaErrorCudartUnloading) { // ignore this error
            throw std::runtime_error("CUDA error.");
        }
    }
}

namespace troy {

    class KernelProvider {

        static bool initialized;
        
    public:

        static void checkInitialized() {
            if (!initialized)
                throw std::invalid_argument("KernelProvider not initialized.");
        }

        static void initialize() {
            cudaError_t status = cudaSetDevice(0);
            printCudaError(status, "set-device", __LINE__, __FILE__);
            initialized = true;
        }

        template <typename T>
        static T* malloc(size_t length) {
            checkInitialized();
            if (length == 0) return nullptr;
            T* ret;
            auto status = cudaMalloc((void**)&ret, length * sizeof(T));
            printCudaError(status, "malloc", __LINE__, __FILE__);
            // printf("Malloc %lu bytes at %p\n", length * sizeof(T), ret);
            return ret;
        }

        template <typename T> 
        static void free(T* pointer) {
            checkInitialized();
            auto status = cudaFree(pointer);
            // printf("Free %p\n", pointer);
            // printCudaError(status, "free", __LINE__, __FILE__);
        }

        template <typename T>
        static void copy(T* deviceDestPtr, const T* hostFromPtr, size_t length) {
            checkInitialized();
            if (length == 0) return;
            auto status = cudaMemcpy(deviceDestPtr, hostFromPtr, length * sizeof(T), cudaMemcpyHostToDevice);
            printCudaError(status, "memcpy-host-to-device", __LINE__, __FILE__);
        }

        template <typename T>
        static void copyOnDevice(T* deviceDestPtr, const T* deviceFromPtr, size_t length) {
            checkInitialized();
            if (length == 0) return;
            auto status = cudaMemcpy(deviceDestPtr, deviceFromPtr, length * sizeof(T), cudaMemcpyDeviceToDevice);
            printCudaError(status, "memcpy-device", __LINE__, __FILE__);
        }

        template <typename T>
        static void retrieve(T* hostDestPtr, const T* deviceFromPtr, size_t length) {
            checkInitialized();
            if (length == 0) return;
            auto status = cudaMemcpy(hostDestPtr, deviceFromPtr, length * sizeof(T), cudaMemcpyDeviceToHost);
            printCudaError(status, "memcpy-device-to-host", __LINE__, __FILE__);
        }

        template <typename T>
        static void memsetZero(T* devicePtr, size_t length) {
            if (length == 0) return;
            auto status = cudaMemset(devicePtr, 0, sizeof(T) * length);
            printCudaError(status, "memset-zero", __LINE__, __FILE__);
        }

    };

}
