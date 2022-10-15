#include "src/troy_cuda.cuh"
#include <cstddef>
#include <cstdint>
#include <ctime>

// using namespace troy;
using namespace std;

using troy::ParmsID;
using troy::SchemeType;
using troy::SecurityLevel;
using troy::Modulus;
using troy::CoeffModulus;
using EncryptionParameters = troy::EncryptionParametersCuda;
using SEALContext = troy::SEALContextCuda;
using Plaintext = troy::PlaintextCuda;
using Ciphertext = troy::CiphertextCuda;
using Encryptor = troy::EncryptorCuda;
using Decryptor = troy::DecryptorCuda;
using Evaluator = troy::EvaluatorCuda;
using KeyGenerator = troy::KeyGeneratorCuda;
using PublicKey = troy::PublicKeyCuda;
using SecretKey = troy::SecretKeyCuda;
using CKKSEncoder = troy::CKKSEncoderCuda;
using BatchEncoder = troy::BatchEncoderCuda;
using KernelProvider = troy::KernelProvider;

#define ASSERT_TRUE(p) if (!(p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_FALSE(p) if ((p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_DOUBLE_EQ(a, b) if (std::fabs((a) - (b)) > 0.01) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_NEAR(a, b, c) if (std::fabs((a) - (b)) > (c)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_EQ(a, b) ASSERT_TRUE((a)==(b))

void test() {
    
        KernelProvider::initialize();
        EncryptionParameters parms(SchemeType::ckks);
        parms.setPolyModulusDegree(64);
        parms.setCoeffModulus(CoeffModulus::Create(64, { 40, 40, 40 }));

        SEALContext context(parms, true, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);

        Encryptor encryptor(context, pk, keygen.secretKey());
        Decryptor decryptor(context, keygen.secretKey());
        CKKSEncoder encoder(context);

        Ciphertext ct;
        Plaintext pt;
        vector<complex<double>> res;
        ParmsID next_parms = context.firstContextData()->nextContextData()->parmsID();
        {
            encryptor.encryptZero(ct);
            ASSERT_FALSE(ct.isTransparent());
            ASSERT_TRUE(ct.isNttForm());
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
            ASSERT_EQ(ct.correctionFactor(), uint64_t(1));
            ct.scale() = pow(2.0, 20);
            decryptor.decrypt(ct, pt);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.real(), 0.0, 0.01);
                ASSERT_NEAR(val.imag(), 0.0, 0.01);
            }

            encryptor.encryptZero(next_parms, ct);
            ASSERT_FALSE(ct.isTransparent());
            ASSERT_TRUE(ct.isNttForm());
            ASSERT_DOUBLE_EQ(ct.scale(), 1.0);
            ASSERT_EQ(ct.correctionFactor(), uint64_t(1));
            ct.scale() = pow(2.0, 20);
            ASSERT_EQ(ct.parmsID(), next_parms);
            decryptor.decrypt(ct, pt);
            ASSERT_EQ(pt.parmsID(), next_parms);
            encoder.decode(pt, res);
            for (auto val : res)
            {
                ASSERT_NEAR(val.real(), 0.0, 0.01);
                ASSERT_NEAR(val.imag(), 0.0, 0.01);
            }
        }
}

int main() {
    test();
    return 0;
}