#pragma once

#include <vector>
#include <exception>

namespace troy { namespace util {
    
template <typename T> class DeviceArray;

template <typename T>
class HostPointer {
    friend class HostArray<T>;
    T* ptr;
    HostPointer(T* p) : ptr(p) {}
public:
    HostPointer(): ptr(nullptr) {}
    bool isNull() {return ptr == nullptr;}
    T* get() {return ptr;}
    HostPointer<T> operator+ (size_t d) const {
        return HostPointer<T>(ptr+d);
    }
    T& operator[](std::size_t i) {return ptr[i];}
    T operator[](std::size_t i) const {return ptr[i];}
    T* operator->() {return ptr;}
    T& operator*() {return *ptr;}
};

template <typename T>
class HostObject {
    T* ptr;
public:
    HostObject(T* p) : ptr(p) {}
    HostObject(): ptr(nullptr) {}
    HostObject(const HostObject& copy) = delete;
    HostObject& operator=(const HostObject& copy) = delete;
    HostObject(HostObject&& move) {
        ptr = move.ptr; move.ptr = null;
    }
    HostObject& operator=(HostObject&& move) {
        if (ptr) delete ptr;
        ptr = move.ptr; move.ptr = null;
    }
    bool isNull() {return ptr == nullptr;}
    const T* get() const {return ptr;}
    T* get() {return ptr;}
    ~HostObject() {
        if (ptr) delete ptr;
    }
    T* operator->() {return ptr;}
    T& operator*() {return *ptr;}
    const T* operator->() const {return ptr;}
    const T& operator*() const {return *ptr;}
};

template <typename T>
class HostArray {
    T* data;
    std::size_t len;
public:
    std::size_t length() const {return len;}

    HostArray() {
        data = nullptr; len = 0;
    }
    HostArray(std::size_t cnt) {
        data = new T[cnt];
        len = cnt;
    }

    HostArray(T* data, std::size_t cnt):
        data(data), len(cnt) {}

    HostArray(const T* copyfrom, std::size_t cnt) {
        data = new T[cnt];
        for (std::size_t i=0; i<cnt; i++) data[i] = copyfrom[i];
        len = cnt;
    }

    HostArray(const std::vector<T>& a) {
        len = a.size();
        data = new T[len];
        for (std::size_t i=0; i<len; i++) data[i] = a[i];
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
    HostArray& operator = (HostArray&& from) {
        if (data) delete[] data;
        data = from.data;
        len = from.len;
        from.data = nullptr;
        from.len = 0;
    }
    HostArray(const HostArray& r) = delete;
    HostArray copy() const {
        return HostArray(data, len);
    }
    T operator[](std::size_t i) const {return data[i];}
    T& operator[](std::size_t i) {return data[i];}
    // DeviceArray<T> toDevice() {
    //     T* copied = KernelProvider::malloc<T>(len);
    //     KernelProvider::copy<T>(copied, data, len);
    //     return DeviceArray<T>(copied, len);
    // }
    T* get() {return data;}
    const T* get() const {return data;}
    HostPointer<T> operator +(size_t d) const {return HostPointer<T>(data + d);}
    HostPointer<T> asPointer() {return HostPointer<T>(data);}

};

}}