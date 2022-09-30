#pragma once

#include <vector>
#include <exception>

namespace troy { namespace util {
    
template <typename T> class DeviceArray;

template <typename T>
class HostArray {
    T* data;
    int len;
public:
    int length() const {return len;}

    HostArray() {
        data = nullptr; len = 0;
    }
    HostArray(int cnt) {
        data = new T[cnt];
        len = cnt;
    }

    HostArray(T* data, int cnt):
        data(data), len(cnt) {}

    HostArray(const T* copyfrom, int cnt) {
        data = new T[cnt];
        for (int i=0; i<cnt; i++) data[i] = copyfrom[i];
        len = cnt;
    }

    HostArray(const std::vector<T>& a) {
        len = a.size();
        data = new T[len];
        for (int i=0; i<len; i++) data[i] = a[i];
    }
    HostArray(HostArray&& arr) {
        data = arr.data; 
        len = arr.len;
        arr.data = nullptr; arr.len = 0;
    }
    ~HostArray() {
        if (data) delete[] data;
    }
    HostArray& operator = (const HostArray& r) = delete;
    HostArray(const HostArray& r) = delete;
    HostArray copy() const {
        return HostArray(data, len);
    }
    T operator[](int i) const {return data[i];}
    T& operator[](int i) {return data[i];}
    // DeviceArray<T> toDevice() {
    //     T* copied = KernelProvider::malloc<T>(len);
    //     KernelProvider::copy<T>(copied, data, len);
    //     return DeviceArray<T>(copied, len);
    // }
    T* get() {return data;}
    const T* get() const {return data;}
};



}}