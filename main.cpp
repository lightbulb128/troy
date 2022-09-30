#include <iostream>
#include <seal/seal.h>

#include "src/devicearray.cuh"
#include "src/modulus.h"

using namespace troy;

using troy::util::HostArray;
using troy::util::DeviceArray;

int main() {

    KernelProvider::initialize();
    std::vector<int> vec;
    for (int i=0; i<10; i++) vec.push_back(i);
    HostArray<int> a(vec);
    DeviceArray<int> d(a);
    HostArray<int> b = d.toHost();
    for (int i=0; i<10; i++) std::cout << b[i] << " ";
    std::cout << "\n";
    printf("Hello world!\n");

    Modulus p(998244354);
    std::cout << (int)(p.isPrime()) << std::endl;

    return 0;
}