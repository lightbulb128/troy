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
#include "src/keygenerator.h"
#include "src/utils/scalingvariant.h"

#include <seal/seal.h>
#include <seal/util/rlwe.h>
#include <seal/util/scalingvariant.h>

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

#define ASSERT_TRUE(p) if (!(p)) std::cout << "===== Assert failed: line " << __LINE__ << "\n"
#define ASSERT_FALSE(p) if ((p)) std::cout << "===== Assert failed: line " << __LINE__ << "\n"
#define ASSERT_EQ(a, b) ASSERT_TRUE((a)==(b))

template <typename T>
void copy(T* a, T* b, size_t count) {
    for (int i=0; i<count; i++) b[i] = a[i];
}

void multiply_add_plain_with_scaling_variant(
    const seal::Plaintext &plain, const seal::SEALContext::ContextData &context_data, seal::util::RNSIter destination)
{
    auto &parms = context_data.parms();
    size_t plain_coeff_count = plain.coeff_count();
    size_t coeff_count = parms.poly_modulus_degree();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto plain_modulus = context_data.parms().plain_modulus();
    auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
    uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
    uint64_t q_mod_t = context_data.coeff_modulus_mod_plain_modulus();
    // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
    // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
    // floor((q * m + floor((t+1) / 2)) / t).
    std::for_each_n(seal::util::iter(plain.data(), size_t(0)), plain_coeff_count, [&](auto I) {
        // Compute numerator = (q mod t) * m[i] + (t+1)/2
        unsigned long long prod[2]{ 0, 0 };
        uint64_t numerator[2]{ 0, 0 };
        seal::util::multiply_uint64(std::get<0>(I), q_mod_t, prod);
        unsigned char carry = seal::util::add_uint64(*prod, plain_upper_half_threshold, numerator);
        numerator[1] = static_cast<uint64_t>(prod[1]) + static_cast<uint64_t>(carry);

        // Compute fix[0] = floor(numerator / t)
        uint64_t fix[2] = { 0, 0 };
        seal::util::divide_uint128_inplace(numerator, plain_modulus.value(), fix);

        // Add to ciphertext: floor(q / t) * m + increment
        size_t coeff_index = std::get<1>(I);
        std::for_each_n(
            seal::util::iter(destination, coeff_modulus, coeff_div_plain_modulus, size_t(0)), coeff_modulus_size, [&](auto J) {
                size_t i = std::get<1>(I), j = std::get<3>(J);
                uint64_t scaled_rounded_coeff = seal::util::multiply_add_uint_mod(std::get<0>(I), std::get<2>(J), fix[0], std::get<1>(J));
                // std::cout << std::get<0>(J)[coeff_index] << std::endl;
                std::get<0>(J)[coeff_index] = seal::util::add_uint_mod(std::get<0>(J)[coeff_index], scaled_rounded_coeff, std::get<1>(J));
                // std::cout << "seal " << i << "," << j << " d[" << (j * plain_coeff_count + i) << "]=" << std::get<0>(J)[coeff_index] << std::endl;
            });
    });
}

void test() {

        EncryptionParameters parms(SchemeType::bfv);
        Modulus plain_modulus(1 << 6);

        seal::EncryptionParameters s_parms(seal::scheme_type::bfv);
        seal::Modulus s_plain_modulus(1<<6);

        parms.setPlainModulus(plain_modulus);
        s_parms.set_plain_modulus(s_plain_modulus);
        {
            parms.setPolyModulusDegree(256);
            parms.setCoeffModulus(CoeffModulus::Create(256, { 40, 40, 40 }));

            s_parms.set_poly_modulus_degree(256);
            s_parms.set_coeff_modulus(seal::CoeffModulus::Create(256, { 40, 40, 40 }));

            SEALContext context(parms, false, SecurityLevel::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.createPublicKey(pk);
            SecretKey sk = keygen.secretKey();

            seal::SEALContext s_context(s_parms, false, seal::sec_level_type::none);
            seal::KeyGenerator s_keygen(s_context);
            seal::PublicKey s_pk;
            s_keygen.create_public_key(s_pk);
            seal::SecretKey s_sk = s_keygen.secret_key();

            copy(pk.data().data(), s_pk.data().data(), pk.data().dynArray().size());
            copy(sk.data().data(), s_sk.data().data(), sk.data().dynArray().size());

            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secretKey());
            encryptor.setSecretKey(keygen.secretKey());

            seal::Encryptor s_encryptor(s_context, s_pk);
            seal::Decryptor s_decryptor(s_context, s_sk);
            s_encryptor.set_secret_key(s_sk);
            

            string hex_poly =
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";

            Ciphertext encrypted;
            Plaintext plain(hex_poly);
            seal::Ciphertext s_encrypted;
            seal::Plaintext s_plain(hex_poly);
            Ciphertext& destination = encrypted;
            seal::Ciphertext& s_destination = s_encrypted;

            encryptor.encryptZero(destination);
            s_encryptor.encrypt_zero(s_destination);
            std::cout << "size = " << destination.dynArray().size() << std::endl;
            ASSERT_EQ(destination.dynArray().size(), s_destination.dyn_array().size());
            copy(destination.data(), s_destination.data(), destination.dynArray().size());
            ::multiply_add_plain_with_scaling_variant(s_plain, *s_context.first_context_data(), seal::util::RNSIter(s_destination.data(0), 256));

            // Multiply plain by scalar coeff_div_plaintext and reposition if in upper-half.
            // Result gets added into the c_0 term of ciphertext (c_0,c_1).

            // encryptZeroInternal(context.firstParmsID(), true, destination);
            util::multiplyAddPlainWithScalingVariant(plain, *context.firstContextData(), HostPointer(destination.data()));


            // encryptor.encrypt(Plaintext(hex_poly), encrypted);
            // copy(s_encrypted.data(), encrypted.data(), s_encrypted.dyn_array().size());
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());
            ASSERT_TRUE(encrypted.parmsID() == context.firstParmsID());
            
            // s_encryptor.encrypt(seal::Plaintext(hex_poly), s_encrypted);
            s_decryptor.decrypt(s_encrypted, s_plain);
            ASSERT_EQ(hex_poly, s_plain.to_string());
            ASSERT_TRUE(s_encrypted.parms_id() == s_context.first_parms_id());

            // copy(encrypted.data(), s_encrypted.data(), encrypted.dynArray().size());
            // s_decryptor.decrypt(s_encrypted, s_plain);
            // ASSERT_EQ(hex_poly, s_plain.to_string());

            ASSERT_EQ(encrypted.dynArray().size(), s_encrypted.dyn_array().size());
            copy(s_encrypted.data(), encrypted.data(), encrypted.dynArray().size());
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(hex_poly, plain.to_string());

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