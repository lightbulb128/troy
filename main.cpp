#include <iostream>
#include <seal/seal.h>

#include "src/utils/ntt.h"
#include "src/utils/hostarray.h"
#include "src/utils/rns.h"
#include "src/encryptionparams.h"
#include "src/kernelprovider.cuh"
#include "src/helper.h"

using namespace troy;
using namespace troy::util;
using std::vector;

void ckks() {
    
    EncryptionParameters parms(SchemeType::ckks);
    size_t poly_modulus_degree = 8192;
    parms.setPolyModulusDegree(poly_modulus_degree);
    parms.setCoeffModulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    double scale = pow(2.0, 40);

    std::cout << parms << std::endl;

}

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

void test() {
    
        auto encryption_parameters_compare = [](SchemeType scheme) {
            EncryptionParameters parms1(scheme);
            parms1.setCoeffModulus(CoeffModulus::Create(64, { 30 }));
            if (scheme == SchemeType::bfv || scheme == SchemeType::bgv)
                parms1.setPlainModulus(1 << 6);
            parms1.setPolyModulusDegree(64);
            parms1.setRandomGenerator(UniformRandomGeneratorFactory::DefaultFactory());

            std::cout << "--- compute id A --- \n";
            parms1.computeParmsID();
            std::cout << parms1 << std::endl;
            std::cout << "before reset" << std::endl;

            EncryptionParameters parms2(parms1);

            parms2.setCoeffModulus(CoeffModulus::Create(64, { 32 }));
            std::cout << "--- compute id B --- \n";
            parms1.computeParmsID();

            std::cout << parms1 << std::endl;
            std::cout << parms2 << std::endl;
        };
        encryption_parameters_compare(SchemeType::bfv);
        // encryption_parameters_compare(SchemeType::bgv);
}

int main() {
    test();
    return 0;
}