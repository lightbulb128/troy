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

void test() {
    
    Modulus plain_t = 0;
    HostObject<RNSTool> rns_tool;
    {
        size_t poly_modulus_degree = 2;
        rns_tool = HostObject(new RNSTool(poly_modulus_degree, RNSBase({ 3 }), plain_t));

        vector<uint64_t> in(poly_modulus_degree * rns_tool->baseq()->size());
        vector<uint64_t> out(poly_modulus_degree * rns_tool->baseBskmTilde()->size());
        setZeroUint(in.size(), in.data());
        auto in_iter = ConstHostPointer(in.data());
        auto out_iter = HostPointer(out.data());
        rns_tool->fastbconvmTilde(in_iter, out_iter);
        // for (auto val : out)
        // {
        //     ASSERT_EQ(0, val);
        // }

        // in[0] = 1;
        // in[1] = 2;
        // rns_tool->fastbconvmTilde(in_iter, out_iter);

        // // These are results for fase base conversion for a length-2 array ((mTilde), (2*mTilde))
        // // before reduction to target base.
        // uint64_t temp = rns_tool->mTilde().value() % 3;
        // uint64_t temp2 = (2 * rns_tool->mTilde().value()) % 3;

        // ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[0].value(), out[0]);
        // ASSERT_EQ(temp2 % (*rns_tool->baseBskmTilde())[0].value(), out[1]);
        // ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[1].value(), out[2]);
        // ASSERT_EQ(temp2 % (*rns_tool->baseBskmTilde())[1].value(), out[3]);
        // ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[2].value(), out[4]);
        // ASSERT_EQ(temp2 % (*rns_tool->baseBskmTilde())[2].value(), out[5]);
    }
    // {
    //     size_t poly_modulus_degree = 2;
    //     size_t coeff_modulus_size = 2;
    //     rns_tool = HostObject(new RNSTool(poly_modulus_degree, RNSBase({ 3, 5 }), plain_t));

    //     vector<uint64_t> in(poly_modulus_degree * coeff_modulus_size);
    //     vector<uint64_t> out(poly_modulus_degree * rns_tool->baseBskmTilde()->size());
    //     setZeroUint(in.size(), in.data());
    //     ConstHostPointer in_iter(in.data());;
    //     HostPointer out_iter(out.data());
    //     rns_tool->fastbconvmTilde(in_iter, out_iter);
    //     for (auto val : out)
    //     {
    //         ASSERT_EQ(0, val);
    //     }

    //     in[0] = 1;
    //     in[1] = 1;
    //     in[2] = 2;
    //     in[3] = 2;
    //     rns_tool->fastbconvmTilde(in_iter, out_iter);
    //     uint64_t mTilde = rns_tool->mTilde().value();

    //     // This is the result of fast base conversion for a length-2 array
    //     // ((mTilde, 2*mTilde), (mTilde, 2*mTilde)) before reduction to target base.
    //     uint64_t temp = ((2 * mTilde) % 3) * 5 + ((4 * mTilde) % 5) * 3;

    //     ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[0].value(), out[0]);
    //     ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[0].value(), out[1]);
    //     ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[1].value(), out[2]);
    //     ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[1].value(), out[3]);
    //     ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[2].value(), out[4]);
    //     ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[2].value(), out[5]);
    //     ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[3].value(), out[6]);
    //     ASSERT_EQ(temp % (*rns_tool->baseBskmTilde())[3].value(), out[7]);
    // }
}

int main() {
    test();
    return 0;
}