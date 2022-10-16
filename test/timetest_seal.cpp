
#include <vector>
#include <string>
#include <sys/time.h>
#include <cassert>
#include <map>
#include <complex>

#include <seal/seal.h>

using std::vector;
using std::complex;

using namespace seal;

namespace troytest {
    
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
                std::cout << p.first << ": " << p.second << std::endl;
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
                evaluator->add_inplace(c3, c1);
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
                evaluator->add_plain(c1, p2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->add_plain_inplace(c3, p2);
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
                evaluator->multiply_plain(c1, p2, c3);
                tim.tock(t1);
                tim.tick(t2);
                evaluator->multiply_plain_inplace(c3, p2);
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
            slotCount = polyModulusDegree / 2;
            this->dataBound = dataBound;
            this->delta = delta;
            EncryptionParameters parms(scheme_type::ckks);
            parms.set_poly_modulus_degree(polyModulusDegree);
            parms.set_coeff_modulus(CoeffModulus::Create(polyModulusDegree, qs));
            context = new SEALContext(parms);
            keygen = new KeyGenerator(*context);
            keygen->create_public_key(pk);
            keygen->create_relin_keys(rlk);
            encoder = new CKKSEncoder(*context);
            encryptor = new Encryptor(*context, pk);
            decryptor = new Decryptor(*context, keygen->secret_key());
            evaluator = new Evaluator(*context);
        }

        ~TimeTestCKKS() {
            if (encoder) delete encoder;
        }
        
        static vector<complex<double>> randomVector(size_t count, int data_bound) {
            vector<complex<double>> input(count, 0.0);
            for (size_t i = 0; i < count; i++)
            {
                input[i] = static_cast<double>(rand() % data_bound);
            }
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
                evaluator->rescale_to_next(c3, c4);
                tim.tock(t2);
                c5 = c1;
                tim.tick(t3);
                evaluator->multiply_inplace(c5, c2);
                tim.tock(t3);
                tim.tick(t4);
                evaluator->rescale_to_next_inplace(c5);
                tim.tock(t4);
            }
            printTimer(tim.gather(repeatCount));
        }

    };

}

int main() {
    troytest::TimeTestCKKS test(16384, {40, 40, 40, 40, 40, 40});
    test.testAdd();
    test.testAddPlain();
    test.testMultiplyRescale();
    test.testMultiplyPlain();
    return 0;
}