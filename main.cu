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

void test2() {
    
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

void test() {
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

    Ciphertext encrypted1;
    Ciphertext encrypted2;
    Plaintext plain1;
    Plaintext plain2;
    Plaintext plainRes;

    vector<complex<double>> input1(slot_size, 0.0);
    vector<complex<double>> input2(slot_size, 0.0);
    vector<complex<double>> expected(slot_size, 0.0);
    vector<complex<double>> output(slot_size);

    int data_bound = (1 << 30);
    const double delta = static_cast<double>(1 << 16);

    srand(static_cast<unsigned>(time(NULL)));

    for (size_t i = 0; i < slot_size; i++)
    {
        input1[i] = static_cast<double>(rand() % data_bound);
        input2[i] = static_cast<double>(rand() % data_bound);
        expected[i] = input1[i] + input2[i];
    }

    encoder.encode(input1, context.firstParmsID(), delta, plain1);
    encoder.encode(input2, context.firstParmsID(), delta, plain2);

    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    CiphertextCuda c1(encrypted1);
    encrypted1 = c1.cpu();

    evaluator.addInplace(encrypted1, encrypted2);

    // Check correctness of encryption
    ASSERT_TRUE(encrypted1.parmsID() == context.firstParmsID());

    decryptor.decrypt(encrypted1, plainRes);
    encoder.decode(plainRes, output);
    double maxDiff = 0;
    for (size_t i = 0; i < slot_size; i++)
    {
        auto tmp = abs(expected[i].real() - output[i].real());
        if (tmp > maxDiff) maxDiff = tmp;
    }
    std::cout << "max difference = " << maxDiff << std::endl;
}

int main() {
    KernelProvider::initialize();
    test2();
    return 0;
}