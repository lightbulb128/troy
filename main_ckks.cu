#include <iostream>
#include <complex>
#include <iomanip>

#include "src/troy_cpu.h"
#include "src/troy_cuda.cuh"

using namespace troy;
using namespace troy::util;
using std::vector;
using std::string;
using std::complex;

#define ASSERT_TRUE(p) if (!(p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_FALSE(p) if ((p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_EQ(a, b) ASSERT_TRUE((a)==(b))

void printVector(const vector<complex<double>>& r, bool onlyreal = false, bool full = false) {
    std::cout << "[";
    for (size_t i = 0; i < r.size(); i++) {
        if (r.size() > 8 && !full && i == 4) {
            std::cout << " ...";
            i = r.size() - 4;
        }
        if (i!=0) std::cout << ", ";
        if (!onlyreal) {
            std::cout << "("; 
            std::cout << std::setprecision(3) << std::fixed << r[i].real();
            std::cout << ", ";
            std::cout << std::setprecision(3) << std::fixed << r[i].imag();
            std::cout << ")";
        } else {
            std::cout << std::setprecision(3) << std::fixed << r[i].real();
            if (r[i].imag() > 0.05) assert(false);
        }
    }
    std::cout << "]" << std::endl;
}

template<typename T>
vector<T> addVector(const vector<T>& a, const vector<T>& b) {
    assert(a.size() == b.size());
    vector<T> ret(a.size());
    for (size_t i = 0; i < a.size(); i++) 
        ret[i] = a[i] + b[i];
    return ret;
}

template<typename T>
vector<T> negateVector(const vector<T>& a) {
    vector<T> ret(a.size());
    for (size_t i = 0; i < a.size(); i++) 
        ret[i] = -a[i];
    return ret;
}

template<typename T>
vector<T> multiplyVector(const vector<T>& a, const vector<T>& b) {
    assert(a.size() == b.size());
    vector<T> ret(a.size());
    for (size_t i = 0; i < a.size(); i++) 
        ret[i] = a[i] * b[i];
    return ret;
}

size_t ceilDiv(size_t a, size_t b) {
    if (a%b) return (a/b+1);
    return a/b;
}

vector<complex<double>> randomVector(size_t count, int data_bound) {
    vector<complex<double>> input(count, 0.0);
    for (size_t i = 0; i < count; i++)
    {
        input[i] = static_cast<double>(rand() % data_bound);
    }
    return input;
}

Ciphertext encrypt(SEALContext& context, CKKSEncoder& encoder, Encryptor& encryptor, const vector<complex<double>>& message, double scale) {
    Plaintext plaintext;
    encoder.encode(message, context.firstParmsID(), scale, plaintext);
    Ciphertext ciphertext;
    encryptor.encrypt(plaintext, ciphertext);
    return ciphertext;
}

CiphertextCuda encryptCuda(SEALContext& context, CKKSEncoder& encoder, Encryptor& encryptor, const vector<complex<double>>& message, double scale) {
    return CiphertextCuda(encrypt(context, encoder, encryptor, message, scale));
}

vector<complex<double>> decrypt(CKKSEncoder& encoder, Decryptor& decryptor, const Ciphertext& ciphertext, size_t slots) {
    Plaintext plaintext;
    decryptor.decrypt(ciphertext, plaintext);
    vector<complex<double>> ret(slots);
    encoder.decode(plaintext, ret);
    return ret;
}  

vector<complex<double>> decryptCuda(CKKSEncoder& encoder, Decryptor& decryptor, const CiphertextCuda& ciphertext, size_t slots) {
    return decrypt(encoder, decryptor, ciphertext.cpu(), slots);
}

#define RANDOM_MESSAGE randomVector(slot_size, data_bound)
#define ENCRYPT(msg) encryptCuda(context, encoder, encryptor, msg, delta)
#define DECRYPT(cipher) decryptCuda(encoder, decryptor, cipher, slot_size)

void test_ckks() {
    
    EncryptionParameters parms(SchemeType::ckks);        
    size_t slot_size = 32;
    parms.setPolyModulusDegree(slot_size * 2);
    parms.setCoeffModulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

    SEALContext context(parms, false, SecurityLevel::none);
    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.createPublicKey(pk);

    CKKSEncoder encoder(context);
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, keygen.secretKey());

    Evaluator evaluator(context);

    SEALContextCuda c_context(context);
    EvaluatorCuda c_evaluator(c_context);

    int data_bound = (1 << 4);
    const double delta = static_cast<double>(1 << 16);

    if (false) { // CKKS add inplace

        auto message1 = randomVector(slot_size, data_bound);
        Plaintext plaintext1;
        encoder.encode(message1, context.firstParmsID(), delta, plaintext1);
        Ciphertext ciphertext1;
        encryptor.encrypt(plaintext1, ciphertext1);
        CiphertextCuda c_ciphertext1(ciphertext1);
        
        auto message2 = randomVector(slot_size, data_bound);
        Plaintext plaintext2;
        encoder.encode(message2, context.firstParmsID(), delta, plaintext2);
        Ciphertext ciphertext2;
        encryptor.encrypt(plaintext2, ciphertext2);
        CiphertextCuda c_ciphertext2(ciphertext2);

        c_evaluator.addInplace(c_ciphertext1, c_ciphertext2);
        
        Ciphertext result = c_ciphertext1.cpu();
        Plaintext decrypted;
        decryptor.decrypt(result, decrypted);
        
        vector<complex<double>> output(slot_size);
        encoder.decode(decrypted, output);
        
        auto mexpect = addVector(message1, message2);
        printVector(mexpect, true);
        printVector(output, true);

    }

    if (false) { // CKKS negate inplace
        auto message = randomVector(slot_size, data_bound);
        CiphertextCuda c1 = encryptCuda(context, encoder, encryptor, message, delta);
        c_evaluator.negateInplace(c1);
        auto decrypted = decryptCuda(encoder, decryptor, c1, slot_size);
        printVector(message, false);
        printVector(decrypted, false);
    }

    if (false) { // ckks multiply inplace
        auto message1 = randomVector(slot_size, data_bound);
        auto message2 = randomVector(slot_size, data_bound);
        auto cipher1 = ENCRYPT(message1);
        auto cipher2 = ENCRYPT(message2);
        c_evaluator.multiplyInplace(cipher1, cipher2);
        auto mmul = DECRYPT(cipher1);
        auto mexpect = multiplyVector(message1, message2);
        printVector(message1, false);
        printVector(message2, false);
        printVector(mmul, false);
        printVector(mexpect, false);
    }

    if (true) { // CKKS square inplace
        auto message = randomVector(slot_size, data_bound);
        CiphertextCuda c1 = encryptCuda(context, encoder, encryptor, message, delta);
        c_evaluator.squareInplace(c1);
        auto decrypted = decryptCuda(encoder, decryptor, c1, slot_size);
        printVector(multiplyVector(message, message), false);
        printVector(decrypted, false);
    }

}

int main() {
    KernelProvider::initialize();
    test_ckks();
    return 0;
}