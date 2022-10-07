#include <iostream>

// #include "src/utils/ntt.h"
#include "src/utils/hostarray.h"
// #include "src/utils/rns.h"
// #include "src/encryptionparams.h"
// #include "src/kernelprovider.cuh"
// #include "src/helper.h"

using namespace troy;
using namespace troy::util;
using std::vector;

// void ckks() {
    
//     EncryptionParameters parms(SchemeType::ckks);
//     size_t poly_modulus_degree = 8192;
//     parms.setPolyModulusDegree(poly_modulus_degree);
//     parms.setCoeffModulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
//     double scale = pow(2.0, 40);

//     std::cout << parms << std::endl;

// }

void kernel() {

    // KernelProvider::initialize();
    // std::vector<int> vec;
    // for (int i=0; i<10; i++) vec.push_back(i);
    // HostArray<int> a(vec);
    // DeviceArray<int> d(a);
    // HostArray<int> b = d.toHost();
    // for (int i=0; i<10; i++) std::cout << b[i] << " ";
    // std::cout << "\n";
    // printf("Hello world!\n");

}

template <typename T, typename S>
void ASSERT_EQ(T a, S b) {
    std::cout << "a = " << a << ", b = " << b << std::endl;
}

void ASSERT_TRUE(bool p) {}
void ASSERT_FALSE(bool p) {}

class Foo {
public:
    HostDynamicArray<int> arr;
    Foo(int p): arr(1) {
        arr[0] = p;
    }
    Foo(const Foo& copy) = default;
};

void test() {
    
    Foo a(1);
    Foo b = a;
    b.arr[0] = 12;
    std::cout << a.arr[0] << " " << b.arr[0] << " " << std::endl;

}

int main() {
    test();
    return 0;
}