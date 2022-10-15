#include "src/troy_cuda.cuh"
#include <cstddef>
#include <cstdint>
#include <ctime>

// using namespace troy;
using namespace std;

using namespace std;
using troy::ParmsID;
using troy::SchemeType;
using troy::SecurityLevel;
using troy::Modulus;
using troy::CoeffModulus;
using troy::PlainModulus;
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
using RelinKeys = troy::RelinKeysCuda;
using GaloisKeys = troy::GaloisKeysCuda;
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
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPolyModulusDegree(128);
        parms.setPlainModulus(plain_modulus);
        parms.setCoeffModulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, SecurityLevel::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.createPublicKey(pk);
        RelinKeys rlk;
        keygen.createRelinKeys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secretKey());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, product;
        Plaintext plain, plain1, plain2, plain3, plain4;

        plain1 = "1x^1";
        plain2 = "1x^10";
        plain3 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        vector<Ciphertext> encrypteds{ encrypted1, encrypted2, encrypted3 };
        evaluator.multiplyMany(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        std::cout << plain.to_string() << std::endl;
        ASSERT_EQ(plain.to_string(), "1x^4 + 2x^3 + 2x^2 + 1x^1");
        ASSERT_TRUE(encrypted1.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted2.parmsID() == product.parmsID());
        ASSERT_TRUE(encrypted3.parmsID() == product.parmsID());
        ASSERT_TRUE(product.parmsID() == context.firstParmsID());
}

int main() {
    test();
    return 0;
}