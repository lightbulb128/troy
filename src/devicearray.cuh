
#include "utils/hostarray.h"
#include "kernelprovider.cuh"
#include <vector>
#include <exception>

namespace troy { namespace util {

template <typename T>
class DeviceArray {
    T* data; int len;
public:
    DeviceArray() {
        data = nullptr; len = 0;
    }
    DeviceArray(int cnt) {
        data = KernelProvider::malloc<T>(cnt);
    }

    // Directly use the given pointer.
    DeviceArray(T* data, int length):
        data(data), len(length) {}

    DeviceArray(DeviceArray&& a) {
        data = a.data; 
        len = a.len;
        a.data = nullptr; a.len = 0;
    }

    DeviceArray(const HostArray<T>& host) {
        len = host.length();
        data = KernelProvider::malloc<T>(len);
        KernelProvider::copy<T>(data, host.get(), len);
    }

    ~DeviceArray() {
        if (data) KernelProvider::free(data);
    }

    DeviceArray& operator = (const DeviceArray& r) = delete;
    DeviceArray(const DeviceArray& r) = delete;
    DeviceArray copy() {
        T* copied = KernelProvider::malloc<T>(len);
        KernelProvider::copyOnDevice<T>(copied, data, len);
        return DeviceArray(copied, len);
    }

    HostArray<T> toHost() {
        T* ret = new T[len];
        KernelProvider::retrieve(ret, data, len);
        return HostArray<T>(ret, len);
    }

};

}}