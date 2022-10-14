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
    RelinKeys rlkcpu;
    keygen.createRelinKeys(rlkcpu);
    RelinKeysCuda rlk(rlkcpu);

    BatchEncoder encoder(context);
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, keygen.secretKey());

    size_t slot_size = encoder.slotCount();

    Evaluator evaluator(context);

    SEALContextCuda c_context(context);
    EvaluatorCuda c_evaluator(c_context);

    int data_bound = (1 << 4);

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

    if (false) { // test rns base
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
        base.decomposeArray(da.asPointer(), 4);
        auto retrieved = da.toHost();
        printVector(ha);
        printVector(retrieved);
        basecpu.composeArray(ha.get(), 4);
        base.composeArray(da.asPointer(), 4);
        retrieved = da.toHost();
        printVector(ha);
        printVector(retrieved);
    }

    if (false) { // test base converter fast convert
        BaseConverter bctcpu(RNSBase({ 2, 3 }), RNSBase({ 3, 4, 5 }));
        BaseConverterCuda bct(bctcpu);
        HostArray<uint64_t> rcpu({ 0, 1, 1, 0, 1, 2 });
        DeviceArray<uint64_t> r(rcpu);
        DeviceArray<uint64_t> rout(9);
        bct.fastConvertArray(r.asPointer(), rout.asPointer(), 3);
        // expect { 0, 1, 2, 0, 3, 1, 0, 2, 0 }
        auto retrieved = rout.toHost();
        printVector(retrieved, true);
    }

    if (false) { // test base converter exact convert
        BaseConverter bctcpu(RNSBase({ 3, 4, 5 }), RNSBase({ 7 }));
        BaseConverterCuda bct(bctcpu);
        HostArray<uint64_t> rcpu({ 0, 1, 2, 0, 3, 1, 0, 2, 0  });
        HostArray<uint64_t> routcpu(3);
        DeviceArray<uint64_t> r(rcpu);
        DeviceArray<uint64_t> rout(3);
        bct.exactConvertArray(r.asPointer(), rout.asPointer(), 3);
        bctcpu.exactConvertArray(rcpu.asPointer(), routcpu.asPointer(), 3);
        auto retrieved = rout.toHost();
        printVector(retrieved, true);
        printVector(routcpu, true);
    }

    if (false) {
        size_t poly_modulus_degree = 2;
        Modulus plain_t = 0;
        RNSTool rns_tool_cpu(poly_modulus_degree, RNSBase({ 3, 5, 7, 11 }), plain_t);
        RNSToolCuda rns_tool(rns_tool_cpu);
        HostArray<uint64_t> rcpu({0,1,0,0,4,0,5,4});
        DeviceArray<uint64_t> r(rcpu);
        std::cout << "before divide\n";
        rns_tool.divideAndRoundqLastInplace(r.asPointer());
        rns_tool_cpu.divideAndRoundqLastInplace(rcpu.asPointer());
        std::cout << "after divide\n";
        HostArray<uint64_t> in = r.toHost();
        printVector(in);
        printVector(rcpu);
    }

    if (false) {
        size_t poly_modulus_degree = 2;
        HostArray<NTTTables> nttcpu(2);
            nttcpu[0] = std::move(NTTTables{ 1, Modulus(53) });
            nttcpu[1] = std::move(NTTTables{ 1, Modulus(13) });
        HostArray<NTTTablesCuda> nttsupport(2);
            nttsupport[0] = NTTTablesCuda(nttcpu[0]);
            nttsupport[1] = NTTTablesCuda(nttcpu[1]);
        DeviceArray<NTTTablesCuda> ntt(nttsupport);
        Modulus plain_t = 0;
        RNSTool rnscpu(poly_modulus_degree, RNSBase({ 53, 13 }), plain_t);
        RNSToolCuda rns(rnscpu);
        HostArray<uint64_t> incpu({25, 35, 12, 9});
        DeviceArray<uint64_t> in(incpu);

        rnscpu.divideAndRoundqLastNttInplace(incpu.asPointer(), nttcpu.get());
        rns   .divideAndRoundqLastNttInplace(in.asPointer(), ntt.asPointer());

        auto ret = in.toHost();
        printVector(ret);
        printVector(incpu);
    }

    if (false) { // test fastbconbsk
        size_t poly_modulus_degree = 2;
        Modulus plain_t = 0;
        RNSTool rnscpu(poly_modulus_degree, RNSBase({ 3, 5 }), plain_t);
        RNSToolCuda rns(rnscpu);
        vector<uint64_t> in(poly_modulus_degree * rnscpu.baseBsk()->size());
        vector<uint64_t> out(poly_modulus_degree * rnscpu.baseq()->size());

        in[0] = 1;
        in[1] = 2;
        in[2] = 1;
        in[3] = 2;
        in[4] = 1;
        in[5] = 2;

        HostArray<uint64_t> rcpu(in);
        DeviceArray<uint64_t> r(rcpu);
        HostArray<uint64_t> dcpu(out);
        DeviceArray<uint64_t> d(4);

        rnscpu.fastbconvSk(rcpu.get(), dcpu.get());
        rns.fastbconvSk(r.asPointer(), d.asPointer());

        printf("dsize = %ld\n", d.size());
        auto retrieve = d.toHost();
        printVector(retrieve);
        // expect {1,2,1,2}
    }

    if (false) { // test smmrq
        size_t poly_modulus_degree = 2;
        Modulus plain_t = 0;
        RNSTool rnscpu(poly_modulus_degree, RNSBase({ 3, 5 }), plain_t);
        RNSToolCuda rns(rnscpu);
        vector<uint64_t> in(poly_modulus_degree * rnscpu.baseBskmTilde()->size());
        vector<uint64_t> out(poly_modulus_degree * rnscpu.baseBsk()->size());

        in[0] = rnscpu.mTilde().value();
        in[1] = 2 * rnscpu.mTilde().value();
        in[2] = rnscpu.mTilde().value();
        in[3] = 2 * rnscpu.mTilde().value();
        in[4] = rnscpu.mTilde().value();
        in[5] = 2 * rnscpu.mTilde().value();
        in[6] = 0;
        in[7] = 0;

        HostArray<uint64_t> rcpu(in);
        DeviceArray<uint64_t> r(rcpu);
        HostArray<uint64_t> dcpu(out);
        DeviceArray<uint64_t> d(6);

        rnscpu.smMrq(rcpu.get(), dcpu.get());
        rns.smMrq(r.asPointer(), d.asPointer());

        printf("dsize = %ld\n", d.size());
        auto retrieve = d.toHost();
        printVector(retrieve);
    }

    

    if (false) { // test fastfloor
        size_t poly_modulus_degree = 2;
        Modulus plain_t = 0;
        RNSTool rnscpu(poly_modulus_degree, RNSBase({ 3, 5 }), plain_t);
        RNSToolCuda rns(rnscpu);
        vector<uint64_t> in(poly_modulus_degree * (rnscpu.baseBsk()->size() + rnscpu.baseq()->size()));
        vector<uint64_t> out(poly_modulus_degree * rnscpu.baseBsk()->size());

        in[0] = 21;
        in[1] = 32;
        in[2] = 21;
        in[3] = 32;
        in[4] = 21;
        in[5] = 32;
        in[6] = 21;
        in[7] = 32;
        in[8] = 21;
        in[9] = 32;

        HostArray<uint64_t> rcpu(in);
        DeviceArray<uint64_t> r(rcpu);
        HostArray<uint64_t> dcpu(out);
        DeviceArray<uint64_t> d(6);

        rnscpu.fastFloor(rcpu.get(), dcpu.get());
        rns.fastFloor(r.asPointer(), d.asPointer());

        printf("dsize = %ld\n", d.size());
        auto retrieve = d.toHost();
        printVector(dcpu);
        printVector(retrieve);
    }
    

    if (false) { // test fastbconvm tilde
        size_t poly_modulus_degree = 2;
        size_t coeff_modulus_size = 2;
        Modulus plain_t = 0;
        RNSTool rnscpu(poly_modulus_degree, RNSBase({ 3, 5 }), plain_t);
        RNSToolCuda rns(rnscpu);
        vector<uint64_t> in(poly_modulus_degree * coeff_modulus_size);
        vector<uint64_t> out(poly_modulus_degree * rnscpu.baseBskmTilde()->size());


        in[0] = 1;
        in[1] = 1;
        in[2] = 2;
        in[3] = 2;

        HostArray<uint64_t> rcpu(in);
        DeviceArray<uint64_t> r(rcpu);
        HostArray<uint64_t> dcpu(out);
        DeviceArray<uint64_t> d(dcpu.size());

        rnscpu.fastbconvmTilde(rcpu.get(), dcpu.get());
        rns.fastbconvmTilde(r.asPointer(), d.asPointer());

        printf("dsize = %ld\n", d.size());
        auto retrieve = d.toHost();
        printVector(dcpu);
        printVector(retrieve);
    }


    

    if (false) { // test decryptScaleAndRound
        size_t poly_modulus_degree = 2;
        Modulus plain_t = 3;
        RNSTool rnscpu(poly_modulus_degree, RNSBase({ 5, 7 }), plain_t);
        RNSToolCuda rns(rnscpu);
        vector<uint64_t> in(poly_modulus_degree * rnscpu.baseBsk()->size());
        vector<uint64_t> out(poly_modulus_degree * rnscpu.baseq()->size());

            in[0] = 29;
            in[1] = 30 + 35;
            in[2] = 29;
            in[3] = 30 + 35;

        HostArray<uint64_t> rcpu(in);
        DeviceArray<uint64_t> r(rcpu);
        HostArray<uint64_t> dcpu(out);
        DeviceArray<uint64_t> d(dcpu.size());

        rnscpu.decryptScaleAndRound(rcpu.get(), dcpu.get());
        rns.decryptScaleAndRound(r.asPointer(), d.asPointer());

        printf("dsize = %ld\n", d.size());
        auto retrieve = d.toHost();
        printVector(dcpu);
        printVector(retrieve);
    }


    if (false) { // BFV multiply inplace
        auto message1 = randomVector(slot_size, data_bound);
        auto message2 = randomVector(slot_size, data_bound);
        printf("before encrypt\n");
        auto cipher1 = ENCRYPT(message1);
        auto cipher2 = ENCRYPT(message2);
        printf("after encrypt\n");
        c_evaluator.multiplyInplace(cipher1, cipher2);
        printf("after mul\n");
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

    if (true) { // BFV relinearize
        auto message = randomVector(slot_size, data_bound);
        Ciphertext ccpu = encrypt(context, encoder, encryptor, message);
        CiphertextCuda c(ccpu);
        evaluator.squareInplace(ccpu);
        evaluator.relinearizeInplace(ccpu, rlkcpu);
        c_evaluator.squareInplace(c);
        c_evaluator.relinearizeInplace(c, rlk);
        auto decrypted = decryptCuda(encoder, decryptor, c, slot_size);
        printVector(multiplyVector(message, message), false);
        printVector(decrypted, false);
    }

}

int main() {
    KernelProvider::initialize();
    test_ckks();
    return 0;
}