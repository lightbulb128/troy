#include <iostream>
#include <seal/seal.h>

#include "src/devicearray.cuh"
#include "src/modulus.h"
#include "src/encryptionparams.h"
#include "src/helper.h"

using namespace troy;

using troy::util::HostArray;
using troy::util::DeviceArray;

void ckks() {
    
    EncryptionParameters parms(SchemeType::ckks);
    size_t poly_modulus_degree = 8192;
    parms.setPolyModulusDegree(poly_modulus_degree);
    parms.setCoeffModulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    double scale = pow(2.0, 40);

    std::cout << parms << std::endl;

}

void kernel() {

    KernelProvider::initialize();
    std::vector<int> vec;
    for (int i=0; i<10; i++) vec.push_back(i);
    HostArray<int> a(vec);
    DeviceArray<int> d(a);
    HostArray<int> b = d.toHost();
    for (int i=0; i<10; i++) std::cout << b[i] << " ";
    std::cout << "\n";
    printf("Hello world!\n");

}

int main() {
    ckks();
    return 0;
}