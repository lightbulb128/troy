#include <iostream>
#include <complex>
#include <iomanip>

#include "src/troy_cpu.h"
#include "src/troy_cuda.cuh"

using namespace troy;
using namespace troy::util;
using std::vector;
using std::string;

#define ASSERT_TRUE(p) if (!(p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_FALSE(p) if ((p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_EQ(a, b) ASSERT_TRUE((a)==(b))

void printVector(const vector<int64_t>& r, bool full = false) {
    std::cout << "[";
    for (size_t i = 0; i < r.size(); i++) {
        if (r.size() > 8 && !full && i == 4) {
            std::cout << " ...";
            i = r.size() - 4;
        }
        if (i!=0) std::cout << ", ";
        std::cout << r[i];
    }
    std::cout << "]" << std::endl;
}

void printVector(const HostArray<uint64_t>& r, bool full = false) {
    std::cout << "[";
    for (size_t i = 0; i < r.size(); i++) {
        if (r.size() > 8 && !full && i == 4) {
            std::cout << " ...";
            i = r.size() - 4;
        }
        if (i!=0) std::cout << ", ";
        std::cout << r[i];
    }
    std::cout << "]" << std::endl;
}


void printVector(const uint64_t* r, size_t size, bool full = false) {
    std::cout << "[";
    for (size_t i = 0; i < size; i++) {
        if (size > 8 && !full && i == 4) {
            std::cout << " ...";
            i = size - 4;
        }
        if (i!=0) std::cout << ", ";
        std::cout << r[i];
    }
    std::cout << "]" << std::endl;
}

template <typename T>
void printVectorT(const T* r, size_t size, bool full = false) {
    std::cout << "[";
    for (size_t i = 0; i < size; i++) {
        if (size > 8 && !full && i == 4) {
            std::cout << " ...";
            i = size - 4;
        }
        if (i!=0) std::cout << ", ";
        std::cout << r[i];
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

vector<int64_t> randomVector(size_t count, int data_bound) {
    vector<int64_t> input(count, 0.0);
    for (size_t i = 0; i < count; i++)
    {
        input[i] = rand() % data_bound;
    }
    return input;
}

Ciphertext encrypt(SEALContext& context, BatchEncoder& encoder, Encryptor& encryptor, const vector<int64_t>& message) {
    Plaintext plaintext;
    encoder.encode(message, plaintext);
    Ciphertext ciphertext;
    encryptor.encrypt(plaintext, ciphertext);
    return ciphertext;
}

CiphertextCuda encryptCuda(SEALContext& context, BatchEncoder& encoder, Encryptor& encryptor, const vector<int64_t>& message) {
    return CiphertextCuda(encrypt(context, encoder, encryptor, message));
}

vector<int64_t> decrypt(BatchEncoder& encoder, Decryptor& decryptor, const Ciphertext& ciphertext, size_t slots) {
    Plaintext plaintext;
    decryptor.decrypt(ciphertext, plaintext);
    vector<int64_t> ret(slots);
    encoder.decode(plaintext, ret);
    return ret;
}  

vector<int64_t> decryptCuda(BatchEncoder& encoder, Decryptor& decryptor, const CiphertextCuda& ciphertext, size_t slots) {
    return decrypt(encoder, decryptor, ciphertext.cpu(), slots);
}

__global__ void printNTTTables(const NTTTablesCuda* c) {
    size_t id = threadIdx.x;
    uint64_t p = DeviceHelper::getModulusValue(c[id].modulus());
    printf("%llu\n", p);
}

#define RANDOM_MESSAGE randomVector(slot_size, data_bound)
#define ENCRYPT(msg) encryptCuda(context, encoder, encryptor, msg)
#define DECRYPT(cipher) decryptCuda(encoder, decryptor, cipher, slot_size)

void test_ckks() {
    
    EncryptionParameters parms(SchemeType::bfv);        
    Modulus plain_modulus(PlainModulus::Batching(64, 20));
    parms.setPolyModulusDegree(64);
    parms.setPlainModulus(plain_modulus);
    parms.setCoeffModulus(CoeffModulus::Create(64, { 30, 30, 30 }));

    SEALContext context(parms, false, SecurityLevel::none);
    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.createPublicKey(pk);

    BatchEncoder encoder(context);
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, keygen.secretKey());

    size_t slot_size = encoder.slotCount();

    Evaluator evaluator(context);

    SEALContextCuda c_context(context);
    EvaluatorCuda c_evaluator(c_context);

    int data_bound = (1 << 4);
    const double delta = static_cast<double>(1 << 16);

    if (false) { // BFV add inplace

        auto message1 = randomVector(slot_size, data_bound);
        Plaintext plaintext1;
        encoder.encode(message1, plaintext1);
        Ciphertext ciphertext1;
        encryptor.encrypt(plaintext1, ciphertext1);
        CiphertextCuda c_ciphertext1(ciphertext1);
        
        auto message2 = randomVector(slot_size, data_bound);
        Plaintext plaintext2;
        encoder.encode(message2, plaintext2);
        Ciphertext ciphertext2;
        encryptor.encrypt(plaintext2, ciphertext2);
        CiphertextCuda c_ciphertext2(ciphertext2);

        c_evaluator.addInplace(c_ciphertext1, c_ciphertext2);
        
        Ciphertext result = c_ciphertext1.cpu();
        Plaintext decrypted;
        decryptor.decrypt(result, decrypted);
        
        vector<int64_t> output(slot_size);
        encoder.decode(decrypted, output);
        
        auto mexpect = addVector(message1, message2);
        printVector(mexpect, true);
        printVector(output, true);

    }

    if (false) { // BFV negate inplace
        auto message = randomVector(slot_size, data_bound);
        CiphertextCuda c1 = encryptCuda(context, encoder, encryptor, message);
        c_evaluator.negateInplace(c1);
        auto decrypted = decryptCuda(encoder, decryptor, c1, slot_size);
        printVector(message, false);
        printVector(decrypted, false);
    }
    

    if (false) { // negacyclic harvey
        size_t polySize = 3;
        size_t coeffModulusSize = 3;
        size_t coeffCountPower = 3;
        size_t coeffCount = 1 << coeffCountPower;
        size_t totalSize = polySize * coeffModulusSize * coeffCount;
        auto p = CoeffModulus::Create(64, { 30, 30, 30 });
        HostArray<NTTTables> nttTablesCpu(4);
        HostArray<NTTTablesCuda> nttTablesCuda(4);
        for (int i=0; i<coeffModulusSize; i++) {
            nttTablesCpu[i] = NTTTables(coeffCountPower, p[i]);
            nttTablesCuda[i] = NTTTablesCuda(nttTablesCpu[i]);
        }
        DeviceArray<NTTTablesCuda> nttTablesDevice(nttTablesCuda);

        HostArray<uint64_t> values(totalSize);
        for (size_t i = 0; i < totalSize; i++) values[i] = i;
        DeviceArray<uint64_t> valuesDevice(values);

        // printNTTTables<<<1, 3>>>(nttTablesDevice.get());
    	HostArray<uint64_t> retrieved = valuesDevice.toHost();
        printVector(retrieved);
        printVector(values);

        std::cout << "doing now." << std::endl;

        util::inverseNttNegacyclicHarveyLazy(values.asPointer(), polySize, coeffModulusSize, nttTablesCpu.get());
        
        std::cout << "kernel do." << std::endl;

        kernel_util::kInverseNttNegacyclicHarveyLazy(valuesDevice.asPointer(), polySize, coeffModulusSize, coeffCountPower, nttTablesDevice.get());

        retrieved = valuesDevice.toHost();
        
        printVector(retrieved);
        printVector(values);

        std::cout << "Finished, destruction." << std::endl;
    }

    if (true) { // 
        auto primes = getPrimes(1024 * 2, 60, 4);
        RNSBase basecpu(primes);
        RNSBaseCuda base(basecpu);
        vector<uint64_t> values{
            0x11111111ul, 0x22222222ul, 0x33333333ul, 0x44444444ul,
            0x55555555ul, 0x66666666ul, 0x77777777ul, 0x88888888ul,
            0x99999999ul, 0xaaaaaaaaul, 0xbbbbbbbbul, 0xccccccccul,
            0xddddddddul, 0xeeeeeeeeul, 0xfffffffful, 0x00000000ul
        };
        HostArray<uint64_t> ha(values);
        DeviceArray<uint64_t> da(ha);
        basecpu.decomposeArray(ha.get(), 4);
        base.decomposeArray(da.asPointer(), 1, 4);
        auto retrieved = da.toHost();
        printVector(ha);
        printVector(retrieved);
        basecpu.composeArray(ha.get(), 4);
        base.composeArray(da.asPointer(), 1, 4);
        retrieved = da.toHost();
        printVector(ha);
        printVector(retrieved);
    }

    if (false) { // BFV multiply inplace
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

    if (false) { // BFV square inplace
        auto message = randomVector(slot_size, data_bound);
        CiphertextCuda c1 = encryptCuda(context, encoder, encryptor, message);
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