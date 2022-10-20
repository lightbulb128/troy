#include "src/troy_cuda.cuh"
#include "src/troy_cpu.h"
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <iomanip>
#include <sys/time.h>

using namespace troy;
using namespace std;

#define ASSERT_TRUE(p) if (!(p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_FALSE(p) if ((p)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_DOUBLE_EQ(a, b) if (std::fabs((a) - (b)) > 0.01) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_NEAR(a, b, c) if (std::fabs((a) - (b)) > (c)) std::cout << "===== Assert failed: line " << std::dec << __LINE__ << "\n"; \
    else std::cout << "ooooo Assert accept: line " << std::dec << __LINE__ << std::endl;
#define ASSERT_EQ(a, b) ASSERT_TRUE((a)==(b))

/*
namespace troytest {

    template<typename T> vector<T> vectorAdd(const vector<T> a, const vector<T> b) {
        assert(a.size() == b.size());
        vector<T> ret; ret.reserve(a.size());
        for (size_t i = 0; i < a.size(); i++) ret.push_back(a[i] + b[i]);
        return ret;
    }

    template<typename T> vector<T> vectorMultiply(const vector<T> a, const vector<T> b) {
        assert(a.size() == b.size());
        vector<T> ret; ret.reserve(a.size());
        for (size_t i = 0; i < a.size(); i++) ret.push_back(a[i] * b[i]);
        return ret;
    }

    template<typename T> vector<T> vectorSub(const vector<T> a, const vector<T> b) {
        assert(a.size() == b.size());
        vector<T> ret; ret.reserve(a.size());
        for (size_t i = 0; i < a.size(); i++) ret.push_back(a[i] - b[i]);
        return ret;
    }

    template<typename T> vector<T> vectorNegate(const vector<T> a) {
        vector<T> ret; ret.reserve(a.size());
        for (size_t i = 0; i < a.size(); i++) ret.push_back(-a[i]);
        return ret;
    }

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
    
    class Timer {
    public:
        std::vector<timeval> times;
        std::vector<double> accumulated; // ms
        std::vector<std::string> names;
        Timer() {}
        long registerTimer(std::string name = "") {
            times.push_back(timeval()); 
            accumulated.push_back(0);
            int ret = times.size() - 1;
            names.push_back(name);
            return ret;
        }
        void tick(long i = 0) {
            if (times.size() < 1) registerTimer();
            assert(i < times.size());
            gettimeofday(&times[i], 0);
        }
        double tock(long i = 0) {
            assert(i < times.size());
            timeval s; gettimeofday(&s, 0);
            auto timeElapsed = (s.tv_sec - times[i].tv_sec) * 1000.0;
            timeElapsed += (s.tv_usec - times[i].tv_usec) / 1000.0;
            accumulated[i] += timeElapsed;
            return accumulated[i];
        }
        
        void clear() {
            times.clear();
            accumulated.clear();
            names.clear();
        }

        std::map<std::string, double> gather(double divisor = 1) {
            std::map<std::string, double> p;
            for (long i=0; i<times.size(); i++) {
                p[names[i]] = accumulated[i] / divisor;
            }
            clear();
            return p;
        }
    };

    class TimeTest {
        
    protected:
        Timer tim;
        Encryptor* encryptor;
        Decryptor* decryptor;
        Evaluator* evaluator;
        SEALContext* context;
        RelinKeys rlk;
        PublicKey pk;
        GaloisKeys gk;
        KeyGenerator* keygen;

    public:
        TimeTest() {
            tim.clear();
            encryptor = nullptr;
            evaluator = nullptr;
            context = nullptr;
            decryptor = nullptr;
        }

        ~TimeTest() {
            if (encryptor) delete encryptor;
            if (evaluator) delete evaluator;
            if (context) delete context;
            if (decryptor) delete decryptor;
            if (keygen) delete keygen;
        }

        virtual Plaintext randomPlaintext() = 0;
        virtual Ciphertext randomCiphertext() = 0;
        // virtual void testEncode() = 0;

        void printTimer(std::map<std::string, double> r) {
            for (auto& p: r) {
                std::cout << std::setw(25) << std::right << p.first << ":";
                std::cout << std::setw(10) << std::right << std::fixed << std::setprecision(3)
                    << p.second << std::endl;
            }
        }

        void testAdd(int repeatCount = 1000) {
            auto c1 = randomCiphertext();
            auto c2 = randomCiphertext();
            Ciphertext c3;
            auto t1 = tim.registerTimer("Add-assign");
            auto t2 = tim.registerTimer("Add-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->add(c1, c2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->addInplace(c3, c1);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testAddPlain(int repeatCount = 1000) {
            auto c1 = randomCiphertext();
            auto p2 = randomPlaintext();
            Ciphertext c3;
            auto t1 = tim.registerTimer("AddPlain-assign");
            auto t2 = tim.registerTimer("AddPlain-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->addPlain(c1, p2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->addPlainInplace(c3, p2);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testMultiplyPlain(int repeatCount = 1000) {
            auto c1 = randomCiphertext();
            auto p2 = randomPlaintext();
            Ciphertext c3;
            auto t1 = tim.registerTimer("MultiplyPlain-assign");
            auto t2 = tim.registerTimer("MultiplyPlain-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->multiplyPlain(c1, p2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->multiplyPlainInplace(c3, p2);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testSquare(int repeatCount = 1000) {
            auto c1 = randomCiphertext();
            Ciphertext c2;
            Ciphertext c3;
            auto t1 = tim.registerTimer("Square-assign");
            auto t2 = tim.registerTimer("Square-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->square(c1, c2);
                tim.tock(t1);
                c3 = c1;
                tim.tick(t2);
                evaluator->squareInplace(c3);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }


    };

    class TimeTestCKKS: public TimeTest {

        CKKSEncoder* encoder;
        size_t slotCount;
        int dataBound;
        double delta;
    
    public:

        TimeTestCKKS(size_t polyModulusDegree, vector<int> qs, int dataBound = 1<<6, double delta=static_cast<double>(1<<16)) {
            KernelProvider::initialize();
            slotCount = polyModulusDegree / 2;
            this->dataBound = dataBound;
            this->delta = delta;
            EncryptionParameters parms(SchemeType::ckks);
            parms.setPolyModulusDegree(polyModulusDegree);
            parms.setCoeffModulus(CoeffModulus::Create(polyModulusDegree, qs));
            context = new SEALContext(parms);
            keygen = new KeyGenerator(*context);
            keygen->createPublicKey(pk);
            keygen->createRelinKeys(rlk);
            keygen->createGaloisKeys(gk);
            encoder = new CKKSEncoder(*context);
            encryptor = new Encryptor(*context, pk);
            decryptor = new Decryptor(*context, keygen->secretKey());
            evaluator = new Evaluator(*context);
        }

        ~TimeTestCKKS() {
            if (encoder) delete encoder;
        }
        
        vector<complex<double>> randomVector(size_t count = 0, int data_bound = 0) {
            if (count == 0) count = slotCount;
            if (data_bound == 0) data_bound = dataBound;
            vector<complex<double>> input(count, 0.0);
            for (size_t i = 0; i < count; i++)
            {
                input[i] = complex<double>(static_cast<double>(rand() % data_bound), static_cast<double>(rand() % data_bound));
            }
            return input;
        }

        vector<complex<double>> constantVector(complex<double> value) {
            size_t count = slotCount;
            vector<complex<double>> input(count, value);
            return input;
        }

        Plaintext randomPlaintext() override {
            auto p = randomVector(slotCount, dataBound);
            Plaintext ret; encoder->encode(p, delta, ret);
            return std::move(ret);
        }

        Ciphertext randomCiphertext() override {
            auto r = randomPlaintext();
            Ciphertext ret; encryptor->encrypt(r, ret);
            return std::move(ret);
        }

        Plaintext encode(const vector<complex<double>>& vec) {
            Plaintext ret; encoder->encode(vec, delta, ret);
            return std::move(ret);
        }

        Ciphertext encrypt(const Plaintext r) {
            Ciphertext ret; encryptor->encrypt(r, ret);
            return std::move(ret);
        }

        Ciphertext encrypt(const vector<complex<double>>& vec) {
            return encrypt(encode(vec));
        }

        Plaintext decryptp(const Ciphertext& c) {
            Plaintext p; decryptor->decrypt(c, p);
            return p;
        }

        vector<complex<double>> decode(const Plaintext& p) {
            vector<complex<double>> ret; encoder->decode(p, ret);
            return ret;
        }

        vector<complex<double>> decrypt(const Ciphertext& c) {
            return decode(decryptp(c));
        }

        void testMultiplyRescale(int repeatCount = 100) {
            auto c1 = randomCiphertext();
            auto c2 = randomCiphertext();
            Ciphertext c3, c4;
            Ciphertext c5;
            auto t1 = tim.registerTimer("Multiply-assign");
            auto t2 = tim.registerTimer("Relinearize-assign");
            auto t3 = tim.registerTimer("Multiply-inplace");
            auto t4 = tim.registerTimer("Relinearize-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->multiply(c1, c2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->rescaleToNext(c3, c4);
                tim.tock(t2);
                c5 = c1;
                tim.tick(t3);
                evaluator->multiplyInplace(c5, c2);
                tim.tock(t3);
                tim.tick(t4);
                evaluator->rescaleToNextInplace(c5);
                tim.tock(t4);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testRotateVector(int repeatCount = 100) {
            auto c1 = randomCiphertext();
            Ciphertext c2;
            auto t1 = tim.registerTimer("Rotate-assign");
            auto t2 = tim.registerTimer("Rotate-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->rotateVector(c1, 1, gk, c2);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->rotateVectorInplace(c1, 1, gk);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testAll() {
            this->testAdd();
            this->testAddPlain();
            this->testMultiplyRescale();
            this->testMultiplyPlain();
            this->testSquare();
            this->testRotateVector();
        }

        void correctMultiply() {
            std::cout << ("Ciphertext multiply") << std::endl;
            auto p1 = randomVector();
            auto p2 = randomVector();
            auto c1 = encrypt(p1);
            auto c2 = encrypt(p2);
            evaluator->multiplyInplace(c1, c2);
            auto p = decrypt(c1);
            auto pp = vectorMultiply(p1, p2);
            printVector(p);
            printVector(pp);
        }

        void correctMultiplyPlain() {
            std::cout << ("Cipher-plain multiply") << std::endl;
            auto p1 = randomVector();
            auto p2 = constantVector(0.5);
            auto c1 = encrypt(p1);
            evaluator->multiplyPlainInplace(c1, encode(p2));
            auto p = decrypt(c1);
            auto pp = vectorMultiply(p1, p2);
            printVector(p);
            printVector(pp);
        }

    };



    class TimeTestBFVBGV: public TimeTest {

        BatchEncoder* encoder;
        size_t slotCount;
        int dataBound;
        double delta;
    
    public:

        TimeTestBFVBGV(bool bgv, size_t polyModulusDegree, uint64_t plainModulusBitSize, vector<int> qs, int dataBound = 1<<6) {
            KernelProvider::initialize();
            slotCount = polyModulusDegree / 2;
            this->dataBound = dataBound;
            this->delta = delta;
            EncryptionParameters parms(bgv ? SchemeType::bgv : SchemeType::bfv);
            parms.setPolyModulusDegree(polyModulusDegree);
            parms.setPlainModulus(PlainModulus::Batching(polyModulusDegree, plainModulusBitSize));
            // parms.setCoeffModulus(CoeffModulus::BFVDefault(polyModulusDegree));
            parms.setCoeffModulus(CoeffModulus::Create(polyModulusDegree, qs));
            context = new SEALContext(parms);
            keygen = new KeyGenerator(*context);
            keygen->createPublicKey(pk);
            keygen->createRelinKeys(rlk);
            keygen->createGaloisKeys(gk);
            encoder = new BatchEncoder(*context);
            encryptor = new Encryptor(*context, pk);
            decryptor = new Decryptor(*context, keygen->secretKey());
            evaluator = new Evaluator(*context);
        }

        ~TimeTestBFVBGV() {
            if (encoder) delete encoder;
        }
        
        static vector<int64_t> randomVector(size_t count, int data_bound) {
            vector<int64_t> input(count, 0.0);
            for (size_t i = 0; i < count; i++)
            {
                input[i] = rand() % data_bound;
            }
            return input;
        }

        Plaintext randomPlaintext() override {
            auto p = randomVector(slotCount, dataBound);
            Plaintext ret; encoder->encode(p, ret);
            return std::move(ret);
        }

        Ciphertext randomCiphertext() override {
            auto r = randomPlaintext();
            Ciphertext ret; encryptor->encrypt(r, ret);
            return std::move(ret);
        }

        void testMultiplyRescale(int repeatCount = 100) {
            auto c1 = randomCiphertext();
            auto c2 = randomCiphertext();
            Ciphertext c3, c4;
            Ciphertext c5;
            auto t1 = tim.registerTimer("Multiply-assign");
            auto t2 = tim.registerTimer("Relinearize-assign");
            auto t3 = tim.registerTimer("Multiply-inplace");
            auto t4 = tim.registerTimer("Relinearize-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->multiply(c1, c2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->modSwitchToNext(c3, c4);
                tim.tock(t2);
                c5 = c1;
                tim.tick(t3);
                evaluator->multiplyInplace(c5, c2);
                tim.tock(t3);
                tim.tick(t4);
                evaluator->modSwitchToNextInplace(c5);
                tim.tock(t4);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testRotateVector(int repeatCount = 100) {
            auto c1 = randomCiphertext();
            Ciphertext c2;
            auto t1 = tim.registerTimer("RotateRows-assign");
            auto t2 = tim.registerTimer("RotateRows-inplace");
            for (int t = 0; t < repeatCount; t++) {
                tim.tick(t1);
                evaluator->rotateRows(c1, 1, gk, c2);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->rotateRowsInplace(c1, 1, gk);
                tim.tock(t2);
            }
            printTimer(tim.gather(repeatCount));
        }

        void testAll() {
            this->testAdd();
            this->testAddPlain();
            this->testMultiplyRescale();
            this->testMultiplyPlain();
            this->testSquare();
            this->testRotateVector();
        }

    };

}
*/

void test() {
    KernelProvider::initialize();

        EncryptionParameters parms(SchemeType::ckks);
        {
            size_t slots = 64;
            parms.setPolyModulusDegree(slots << 1);
            parms.setCoeffModulus(CoeffModulus::Create(slots << 1, { 40, 40, 40, 40, 40 }));
            SEALContext context(parms, false, SecurityLevel::none);
            SEALContextCuda c_context(context);

            vector<complex<double>> values(slots);

            srand(static_cast<unsigned>(time(NULL)));
            int data_bound = (1 << 20);

            for (size_t i = 0; i < slots; i++)
            {
                complex<double> value(static_cast<double>(rand() % data_bound), 0);
                values[i] = value;
            }

            CKKSEncoder encoder(context);
            CKKSEncoderCuda c_encoder(c_context);
            {
                // Use a very large scale
                double delta = pow(2.0, 110);
                Plaintext plain;
                PlaintextCuda c_plain;

                encoder.encode(values, context.firstParmsID(), delta, plain);
                vector<complex<double>> result;
                encoder.decode(plain, result);

                for (size_t i = 0; i < 3; ++i)
                {
                    auto tmp = abs(values[i].real() - result[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }

                c_encoder.encode(values, context.firstParmsID(), delta, c_plain);
                c_encoder.decode(c_plain, result);

                for (size_t i = 0; i < 3; ++i)
                {
                    auto tmp = abs(values[i].real() - result[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
            // {
            //     // Use a scale over 128 bits
            //     double delta = pow(2.0, 130);
            //     Plaintext plain;
            //     encoder.encode(values, context.firstParmsID(), delta, plain);
            //     vector<complex<double>> result;
            //     encoder.decode(plain, result);

            //     for (size_t i = 0; i < slots; ++i)
            //     {
            //         auto tmp = abs(values[i].real() - result[i].real());
            //         ASSERT_TRUE(tmp < 0.5);
            //     }
            // }
        }
}

int main() {

    test();

    // std::cout << "----- CKKS -----\n";
    // troytest::TimeTestCKKS test(16384, {40, 40, 40, 40, 40, 40}, 64, 1<<30);
    // test.correctMultiply();
    // test.correctMultiplyPlain();
    // test.testAll();

    // std::cout << "----- BFV -----\n";
    // troytest::TimeTestBFVBGV test2(false, 16384, 20, {40, 40, 40, 40, 40, 40});
    // test2.testAll();

    // std::cout << "----- BGV -----\n";
    // troytest::TimeTestBFVBGV test3(true, 16384, 20, {40, 40, 40, 40, 40, 40});
    // test3.testAll();
    return 0;
}