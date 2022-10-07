#pragma once

#include <vector>
#include <exception>

namespace troy { namespace util {
    
template <typename T> class DeviceArray;
template <typename T> class HostArray;

template <typename T>
class HostPointer {
    T* ptr;
public:
    HostPointer(T* p) : ptr(p) {}
    HostPointer(): ptr(nullptr) {}
    bool isNull() {return ptr == nullptr;}
    T* get() {return ptr;}
    const T* get() const {return ptr;}
    HostPointer<T> operator+ (size_t d) const {
        return HostPointer<T>(ptr+d);
    }
    T& operator[](std::size_t i) {return ptr[i];}
    const T& operator[](std::size_t i) const {return ptr[i];}
    T* operator->() {return ptr;}
    T& operator*() {return *ptr;}
    HostPointer& operator++() {ptr++; return *this;}
    HostPointer operator++(int) {HostPointer copied = *this; ptr++; return copied;}
};

template <typename T>
class ConstHostPointer {
    const T* ptr;
public:
    ConstHostPointer(const T* p) : ptr(p) {}
    ConstHostPointer(): ptr(nullptr) {}
    ConstHostPointer(const HostPointer<T>& h): ptr(h.get()) {}
    bool isNull() {return ptr == nullptr;}
    const T* get() {return ptr;}
    ConstHostPointer<T> operator+ (size_t d) const {
        return ConstHostPointer<T>(ptr+d);
    }
    const T& operator[](std::size_t i) const {return ptr[i];}
    const T* operator->() {return ptr;}
    const T& operator*() {return *ptr;}
    ConstHostPointer& operator++() {ptr++; return *this;}
    ConstHostPointer operator++(int) {ConstHostPointer copied = *this; ptr++; return copied;}
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
        ptr = move.ptr; move.ptr = nullptr;
    }
    HostObject& operator=(HostObject&& move) {
        if (ptr) delete ptr;
        ptr = move.ptr; move.ptr = nullptr;
        return *this;
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
        if (cnt > 0) data = new T[cnt];
        else data = nullptr;
        len = cnt;
    }

    HostArray(T* data, std::size_t cnt):
        data(data), len(cnt) {}

    HostArray(const T* copyfrom, std::size_t cnt) {
        if (cnt == 0) {data = nullptr; len = 0; return;}
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
        return *this;
    }
    HostArray(const HostArray& r) = delete;
    HostArray copy() const {
        return HostArray(data, len);
    }
    const T& operator[](std::size_t i) const {return data[i];}
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