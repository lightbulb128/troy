#include <iostream>

// #include "src/utils/ntt.h"
#include "src/utils/hostarray.h"
#include "src/utils/rlwe.h"
// #include "src/utils/rns.h"
#include "src/encryptionparams.h"
// #include "src/kernelprovider.cuh"
#include "src/helper.h"
#include "src/encryptor.h"
#include "src/decryptor.h"
#include "src/evaluator.h"
#include "src/keygenerator.h"
#include "src/utils/scalingvariant.h"

#include <seal/seal.h>
#include "sealhelper.h"

using namespace troy;
using namespace troy::util;
using std::vector;
using std::string;

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

#define ASSERT_TRUE(p) if (!(p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_FALSE(p) if ((p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_EQ(a, b) ASSERT_TRUE((a)==(b))

template <typename T>
void copy(const T* a, T* b, size_t count) {
    for (int i=0; i<count; i++) b[i] = a[i];
}


void test() {

        uint64_t plain_modulus_ = 65;
        size_t degree = 128;
        auto qs = {60, 60, 60, 60};

        EncryptionParameters parms(SchemeType::bgv);
        Modulus plain_modulus(plain_modulus_);

        seal::EncryptionParameters s_parms(seal::scheme_type::bgv);
        seal::Modulus s_plain_modulus(plain_modulus_);

        parms.setPlainModulus(plain_modulus);
        s_parms.set_plain_modulus(s_plain_modulus);
        {
            parms.setPolyModulusDegree(degree);
            parms.setCoeffModulus(CoeffModulus::Create(degree, qs));

            s_parms.set_poly_modulus_degree(degree);
            s_parms.set_coeff_modulus(seal::CoeffModulus::Create(degree, qs));


            seal::SEALContext s_context(s_parms, false, seal::sec_level_type::none);
            seal::KeyGenerator s_keygen(s_context);
            seal::PublicKey s_pk;
            seal::RelinKeys s_rlk;
            seal::SecretKey s_sk = s_keygen.secret_key();

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            RelinKeys rlk;
            SecretKey sk = keygen.secretKey();

            // // copy keys from troy to seal
            // copy(sk.data().data(), s_sk.data().data(), sk.data().dynArray().size());
            keygen.setSecretKeyFromExternal(s_sk.data().data());
            // copy(s_sk.data().data(), sk.data().data(), sk.data().dynArray().size());

            // sealhelper::compute_secret_key_array(s_sk.data().data(), *s_context.key_context_data(), 2);
            
            s_keygen.create_public_key(s_pk);
            s_keygen.create_relin_keys(s_rlk);
            keygen.createPublicKey(pk);
            keygen.createRelinKeys(rlk);

            copy(pk.data().data(), s_pk.data().data(), pk.data().dynArray().size());
            for (size_t i = 0; i < rlk.data().size(); i++) {
                for (size_t j = 0; j < rlk.data()[i].size(); j++) 
                    copy(rlk.data()[i][j].data().data(), 
                        s_rlk.data()[i][j].data().data(),
                        rlk.data()[i][j].data().dynArray().size());
            }

            // copy(s_pk.data().data(), pk.data().data(), pk.data().dynArray().size());
            // assert(rlk.data().size() == s_rlk.data().size());
            // for (size_t i = 0; i < rlk.data().size(); i++) {
            //     assert(rlk.data()[i].size() == s_rlk.data()[i].size());
            //     for (size_t j = 0; j < rlk.data()[i].size(); j++) 
            //         copy(s_rlk.data()[i][j].data().data(), 
            //             rlk.data()[i][j].data().data(),
            //             rlk.data()[i][j].data().dynArray().size());
            // }

            std::cout << "  pk: "; printArray(pk.data().data(), pk.data().dynArray().size());
            std::cout << "s_pk: "; printArray(s_pk.data().data(), s_pk.data().dyn_array().size());

            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            Evaluator evaluator(context);
            encryptor.setSecretKey(sk);

            seal::Encryptor s_encryptor(s_context, s_pk);
            seal::Decryptor s_decryptor(s_context, s_sk);
            seal::Evaluator s_evaluator(s_context);
            s_encryptor.set_secret_key(s_sk);
            
            Plaintext plain, plain1, plain2;
            Plaintext plain_multiplier;
            Ciphertext encrypted, encrypted1, encrypted2;
            seal::Plaintext s_plain, s_plain1, s_plain2;
            seal::Plaintext s_plain_multiplier;
            seal::Ciphertext s_encrypted, s_encrypted1, s_encrypted2;


            plain = 0;
            encryptor.encrypt(plain, encrypted);

            s_plain = 0;
            s_encryptor.encrypt(s_plain, s_encrypted);
            copy(encrypted.data(), s_encrypted.data(), encrypted.dynArray().size());

            evaluator.squareInplace(encrypted);
            s_evaluator.square_inplace(s_encrypted);

            std::cout << "square troy: "; printArray(encrypted.data(), encrypted.dynArray().size());
            std::cout << "square seal: "; printArray(s_encrypted.data(), encrypted.dynArray().size());

            evaluator.relinearizeInplace(encrypted, rlk);
            sealhelper::relinearize_internal(s_context, s_encrypted, s_rlk, 2);

            decryptor.decrypt(encrypted, plain2);
            s_decryptor.decrypt(s_encrypted, s_plain2);

            ASSERT_TRUE(plain == plain2);
            ASSERT_TRUE(s_plain == s_plain2);

        }
}

void test2() {
        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);
        parms.setPlainModulus(plain_modulus);
        {

            parms.setPolyModulusDegree(256);
            parms.setCoeffModulus(CoeffModulus::Create(256, { 40, 40, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);

            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());

            Ciphertext encrypted;
            Plaintext plain;
            string hex_poly;

            hex_poly =
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            encryptor.encrypt(Plaintext(hex_poly), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            hex_poly = "0";
            encryptor.encrypt(Plaintext(hex_poly), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            hex_poly = "1";
            encryptor.encrypt(Plaintext(hex_poly), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            hex_poly = "1x^1";
            encryptor.encrypt(Plaintext(hex_poly), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            hex_poly =
                "1x^62 + 1x^61 + 1x^60 + 1x^59 + 1x^58 + 1x^57 + 1x^56 + 1x^55 + 1x^54 + 1x^53 + 1x^52 + 1x^51 + 1x^50 "
                "+ 1x^49 + 1x^48 + 1x^47 + 1x^46 + 1x^45 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 1x^40 + 1x^39 + 1x^38 + "
                "1x^37 + 1x^36 + 1x^35 + 1x^34 + 1x^33 + 1x^32 + 1x^31 + 1x^30 + 1x^29 + 1x^28 + 1x^27 + 1x^26 + 1x^25 "
                "+ 1x^24 + 1x^23 + 1x^22 + 1x^21 + 1x^20 + 1x^19 + 1x^18 + 1x^17 + 1x^16 + 1x^15 + 1x^14 + 1x^13 + "
                "1x^12 + 1x^11 + 1x^10 + 1x^9 + 1x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1";
            encryptor.encrypt(Plaintext(hex_poly), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            hex_poly =
                "1x^62 + 1x^61 + 1x^60 + 1x^59 + 1x^58 + 1x^57 + 1x^56 + 1x^55 + 1x^54 + 1x^53 + 1x^52 + 1x^51 + 1x^50 "
                "+ 1x^49 + 1x^48 + 1x^47 + 1x^46 + 1x^45 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 1x^40 + 1x^39 + 1x^38 + "
                "1x^37 + 1x^36 + 1x^35 + 1x^34 + 1x^33 + 1x^32 + 1x^31 + 1x^30 + 1x^29 + 1x^28 + 1x^27 + 1x^26 + 1x^25 "
                "+ 1x^24 + 1x^23 + 1x^22 + 1x^21 + 1x^20 + 1x^19 + 1x^18 + 1x^17 + 1x^16 + 1x^15 + 1x^14 + 1x^13 + "
                "1x^12 + 1x^11 + 1x^10 + 1x^9 + 1x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1x^1";
            encryptor.encrypt(Plaintext(hex_poly), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            hex_poly =
                "1x^62 + 1x^61 + 1x^60 + 1x^59 + 1x^58 + 1x^57 + 1x^56 + 1x^55 + 1x^54 + 1x^53 + 1x^52 + 1x^51 + 1x^50 "
                "+ 1x^49 + 1x^48 + 1x^47 + 1x^46 + 1x^45 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 1x^40 + 1x^39 + 1x^38 + "
                "1x^37 + 1x^36 + 1x^35 + 1x^34 + 1x^33 + 1x^32 + 1x^31 + 1x^30 + 1x^29 + 1x^28 + 1x^27 + 1x^26 + 1x^25 "
                "+ 1x^24 + 1x^23 + 1x^22 + 1x^21 + 1x^20 + 1x^19 + 1x^18 + 1x^17 + 1x^16 + 1x^15 + 1x^14 + 1x^13 + "
                "1x^12 + 1x^11 + 1x^10 + 1x^9 + 1x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1x^1 + 1";
            encryptor.encrypt(Plaintext(hex_poly), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());

            hex_poly =
                "1x^28 + 1x^25 + 1x^23 + 1x^21 + 1x^20 + 1x^19 + 1x^16 + 1x^15 + 1x^13 + 1x^12 + 1x^7 + 1x^5 + 1";
            encryptor.encrypt(Plaintext(hex_poly), encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
        }
}

int main() {
    test();
    return 0;
}