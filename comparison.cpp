#include <seal/seal.h>
#include <string>
#include <sstream>

using namespace seal;
using std::string;
using std::stringstream;

#define ASSERT_TRUE(p) if (!(p)) std::cout << "Assert failed: line " << __LINE__ << "\n"
#define ASSERT_FALSE(p) if ((p)) std::cout << "Assert failed: line " << __LINE__ << "\n"
#define ASSERT_EQ(a, b) ASSERT_TRUE((a)==(b))

int main () {
    
    EncryptionParameters parms(scheme_type::bfv);
    Modulus plain_modulus(1 << 6);
    parms.set_plain_modulus(plain_modulus);
    {
        parms.set_poly_modulus_degree(128);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));
        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;
        string hex_poly;

        hex_poly =
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        std::cout << plain.to_string() << std::endl;
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly = "0";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly = "1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly = "1x^1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^62 + 1x^61 + 1x^60 + 1x^59 + 1x^58 + 1x^57 + 1x^56 + 1x^55 + 1x^54 + 1x^53 + 1x^52 + 1x^51 + 1x^50 "
            "+ 1x^49 + 1x^48 + 1x^47 + 1x^46 + 1x^45 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 1x^40 + 1x^39 + 1x^38 + "
            "1x^37 + 1x^36 + 1x^35 + 1x^34 + 1x^33 + 1x^32 + 1x^31 + 1x^30 + 1x^29 + 1x^28 + 1x^27 + 1x^26 + 1x^25 "
            "+ 1x^24 + 1x^23 + 1x^22 + 1x^21 + 1x^20 + 1x^19 + 1x^18 + 1x^17 + 1x^16 + 1x^15 + 1x^14 + 1x^13 + "
            "1x^12 + 1x^11 + 1x^10 + 1x^9 + 1x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^62 + 1x^61 + 1x^60 + 1x^59 + 1x^58 + 1x^57 + 1x^56 + 1x^55 + 1x^54 + 1x^53 + 1x^52 + 1x^51 + 1x^50 "
            "+ 1x^49 + 1x^48 + 1x^47 + 1x^46 + 1x^45 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 1x^40 + 1x^39 + 1x^38 + "
            "1x^37 + 1x^36 + 1x^35 + 1x^34 + 1x^33 + 1x^32 + 1x^31 + 1x^30 + 1x^29 + 1x^28 + 1x^27 + 1x^26 + 1x^25 "
            "+ 1x^24 + 1x^23 + 1x^22 + 1x^21 + 1x^20 + 1x^19 + 1x^18 + 1x^17 + 1x^16 + 1x^15 + 1x^14 + 1x^13 + "
            "1x^12 + 1x^11 + 1x^10 + 1x^9 + 1x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1x^1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^62 + 1x^61 + 1x^60 + 1x^59 + 1x^58 + 1x^57 + 1x^56 + 1x^55 + 1x^54 + 1x^53 + 1x^52 + 1x^51 + 1x^50 "
            "+ 1x^49 + 1x^48 + 1x^47 + 1x^46 + 1x^45 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 1x^40 + 1x^39 + 1x^38 + "
            "1x^37 + 1x^36 + 1x^35 + 1x^34 + 1x^33 + 1x^32 + 1x^31 + 1x^30 + 1x^29 + 1x^28 + 1x^27 + 1x^26 + 1x^25 "
            "+ 1x^24 + 1x^23 + 1x^22 + 1x^21 + 1x^20 + 1x^19 + 1x^18 + 1x^17 + 1x^16 + 1x^15 + 1x^14 + 1x^13 + "
            "1x^12 + 1x^11 + 1x^10 + 1x^9 + 1x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^28 + 1x^25 + 1x^23 + 1x^21 + 1x^20 + 1x^19 + 1x^16 + 1x^15 + 1x^13 + 1x^12 + 1x^7 + 1x^5 + 1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }
    {
        parms.set_poly_modulus_degree(256);
        parms.set_coeff_modulus(CoeffModulus::Create(256, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;
        string hex_poly;

        hex_poly =
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly = "0";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly = "1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly = "1x^1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^62 + 1x^61 + 1x^60 + 1x^59 + 1x^58 + 1x^57 + 1x^56 + 1x^55 + 1x^54 + 1x^53 + 1x^52 + 1x^51 + 1x^50 "
            "+ 1x^49 + 1x^48 + 1x^47 + 1x^46 + 1x^45 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 1x^40 + 1x^39 + 1x^38 + "
            "1x^37 + 1x^36 + 1x^35 + 1x^34 + 1x^33 + 1x^32 + 1x^31 + 1x^30 + 1x^29 + 1x^28 + 1x^27 + 1x^26 + 1x^25 "
            "+ 1x^24 + 1x^23 + 1x^22 + 1x^21 + 1x^20 + 1x^19 + 1x^18 + 1x^17 + 1x^16 + 1x^15 + 1x^14 + 1x^13 + "
            "1x^12 + 1x^11 + 1x^10 + 1x^9 + 1x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^62 + 1x^61 + 1x^60 + 1x^59 + 1x^58 + 1x^57 + 1x^56 + 1x^55 + 1x^54 + 1x^53 + 1x^52 + 1x^51 + 1x^50 "
            "+ 1x^49 + 1x^48 + 1x^47 + 1x^46 + 1x^45 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 1x^40 + 1x^39 + 1x^38 + "
            "1x^37 + 1x^36 + 1x^35 + 1x^34 + 1x^33 + 1x^32 + 1x^31 + 1x^30 + 1x^29 + 1x^28 + 1x^27 + 1x^26 + 1x^25 "
            "+ 1x^24 + 1x^23 + 1x^22 + 1x^21 + 1x^20 + 1x^19 + 1x^18 + 1x^17 + 1x^16 + 1x^15 + 1x^14 + 1x^13 + "
            "1x^12 + 1x^11 + 1x^10 + 1x^9 + 1x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1x^1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^62 + 1x^61 + 1x^60 + 1x^59 + 1x^58 + 1x^57 + 1x^56 + 1x^55 + 1x^54 + 1x^53 + 1x^52 + 1x^51 + 1x^50 "
            "+ 1x^49 + 1x^48 + 1x^47 + 1x^46 + 1x^45 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 1x^40 + 1x^39 + 1x^38 + "
            "1x^37 + 1x^36 + 1x^35 + 1x^34 + 1x^33 + 1x^32 + 1x^31 + 1x^30 + 1x^29 + 1x^28 + 1x^27 + 1x^26 + 1x^25 "
            "+ 1x^24 + 1x^23 + 1x^22 + 1x^21 + 1x^20 + 1x^19 + 1x^18 + 1x^17 + 1x^16 + 1x^15 + 1x^14 + 1x^13 + "
            "1x^12 + 1x^11 + 1x^10 + 1x^9 + 1x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^28 + 1x^25 + 1x^23 + 1x^21 + 1x^20 + 1x^19 + 1x^16 + 1x^15 + 1x^13 + 1x^12 + 1x^7 + 1x^5 + 1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }
    {
        parms.set_poly_modulus_degree(256);
        parms.set_coeff_modulus(CoeffModulus::Create(256, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;
        string hex_poly;
        stringstream stream;

        hex_poly =
            "1x^28 + 1x^25 + 1x^23 + 1x^21 + 1x^20 + 1x^19 + 1x^16 + 1x^15 + 1x^13 + 1x^12 + 1x^7 + 1x^5 + 1";
        encryptor.encrypt(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^28 + 1x^25 + 1x^23 + 1x^21 + 1x^20 + 1x^19 + 1x^16 + 1x^15 + 1x^13 + 1x^12 + 1x^7 + 1x^5 + 1";
        encryptor.encrypt(Plaintext(hex_poly)).save(stream);
        encrypted.load(context, stream);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }
    {
        parms.set_poly_modulus_degree(256);
        parms.set_coeff_modulus(CoeffModulus::Create(256, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;
        string hex_poly;
        stringstream stream;

        hex_poly =
            "1x^28 + 1x^25 + 1x^23 + 1x^21 + 1x^20 + 1x^19 + 1x^16 + 1x^15 + 1x^13 + 1x^12 + 1x^7 + 1x^5 + 1";
        encryptor.encrypt_symmetric(Plaintext(hex_poly), encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        hex_poly =
            "1x^28 + 1x^25 + 1x^23 + 1x^21 + 1x^20 + 1x^19 + 1x^16 + 1x^15 + 1x^13 + 1x^12 + 1x^7 + 1x^5 + 1";
        encryptor.encrypt_symmetric(Plaintext(hex_poly)).save(stream);
        encrypted.load(context, stream);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(hex_poly, plain.to_string());
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }
    return 0;
}