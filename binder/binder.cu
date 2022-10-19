#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>

#include "../src/troy_cuda.cuh"
#include <iostream>
#include <memory.h>

namespace py = pybind11;

using namespace troyn;
using std::vector;
using std::complex;
using std::stringstream;
using std::istringstream;
using std::ostringstream;
using std::string;

#define SAVE_MACRO ostringstream stream; p.save(stream); return py::bytes(stream.str());
#define LOAD_MACRO istringstream stream(str);  self.load(stream);

class Smoke {
public:
    int t;
    Smoke(int i) {t=i;}
    Smoke() {t=19991111;}
    void print() {std::cout << "Hello I am Smoking ... " << t << std::endl;}
};

void initializeKernel() {
    KernelProvider::initialize();
}

template<typename T>
std::vector<T> hostArrayToVector(const troy::util::HostArray<T>& from) {
    std::vector<T> ret; ret.reserve(from.size());
    for (size_t i = 0; i < from.size(); i++)
        ret.push_back(from[i]);
    return ret;
}

template<typename T>
std::vector<T> deviceArrayToVector(const troy::util::DeviceArray<T>& from) {
    return hostArrayToVector(from.toHost());
}

PYBIND11_MODULE(pytroy, m) {

    m.def("initialize_kernel", &initializeKernel);
    
    py::class_<Smoke>(m, "Smoke")
        .def(py::init<>())
        .def(py::init<int>())
        .def("hello", &Smoke::print);

    py::enum_<SchemeType>(m, "SchemeType")
        .value("none", SchemeType::none)
        .value("bfv", SchemeType::bfv)
        .value("bgv", SchemeType::bgv)
        .value("ckks", SchemeType::ckks);

    py::enum_<SecurityLevel>(m, "SecurityLevel")
        .value("none", SecurityLevel::none)
        .value("tc128", SecurityLevel::tc128)
        .value("tc192", SecurityLevel::tc192)
        .value("tc256", SecurityLevel::tc256)
        ;

    py::class_<Modulus>(m, "Modulus")
        .def(py::init<uint64_t>())
        .def("is_prime", &Modulus::isPrime)
        .def("value", &Modulus::value)
        ;

    py::class_<CoeffModulus>(m, "CoeffModulus")
        .def_static("max_bit_count", &CoeffModulus::MaxBitCount, 
            py::arg("poly_modulus_degree"), py::arg("sec_level") = SecurityLevel::tc128)
        .def_static("bfv_default", &CoeffModulus::BFVDefault, 
            py::arg("poly_modulus_degree"), py::arg("sec_level") = SecurityLevel::tc128)
        .def_static("create", py::overload_cast<size_t, std::vector<int>>(&CoeffModulus::Create))
        .def_static("create", py::overload_cast<size_t, const Modulus&, std::vector<int>>(&CoeffModulus::Create))
        ;

    py::class_<PlainModulus>(m, "PlainModulus")
        .def_static("batching", py::overload_cast<size_t, int>(&PlainModulus::Batching))
        .def_static("batching", py::overload_cast<size_t, std::vector<int>>(&PlainModulus::Batching))
        ;

    py::class_<ParmsID>(m, "ParmsID")
        .def("vec", [](const ParmsID& p){
            std::vector<uint64_t> ret;
            ret.reserve(troy::util::HashFunction::hash_block_uint64_count);
            for (size_t i = 0; i < ret.size(); i++) {
                ret.push_back(p[i]);
            }
            return ret;
        });

    py::class_<EncryptionParameters>(m, "EncryptionParameters")
        .def(py::init<SchemeType>())
        .def("set_poly_modulus_degree", &EncryptionParameters::setPolyModulusDegree)
        .def("set_coeff_modulus", &EncryptionParameters::setCoeffModulus)
        .def("set_plain_modulus", py::overload_cast<uint64_t>(&EncryptionParameters::setPlainModulus))
        .def("set_plain_modulus", py::overload_cast<const Modulus&>(&EncryptionParameters::setPlainModulus))
        .def("scheme", &EncryptionParameters::scheme)
        .def("poly_modulus_degree", &EncryptionParameters::polyModulusDegree)
        .def("coeff_modulus", [](const EncryptionParameters& self) {
            return deviceArrayToVector(self.coeffModulus());
        })
        .def("parms_id", &EncryptionParameters::parmsID)
        ;

    py::class_<SEALContext::ContextDataCuda>(m, "ContextData")
        .def("parms", &SEALContext::ContextDataCuda::parms)
        .def("parms_id", &SEALContext::ContextDataCuda::parmsID)
        .def("chain_index", &SEALContext::ContextDataCuda::chainIndex)
        .def("prev_context_data", &SEALContext::ContextDataCuda::prevContextData)
        .def("next_context_data", &SEALContext::ContextDataCuda::nextContextData)
        ;

    py::class_<SEALContext>(m, "SEALContext")
        .def(py::init<EncryptionParameters, bool, SecurityLevel>(),
            py::arg("parms"),
            py::arg("expand_mod_chain") = true, py::arg("sec_level") = SecurityLevel::tc128)
        .def("get_context_data", &SEALContext::getContextData)
        .def("first_context_data", &SEALContext::firstContextData)
        .def("last_context_data", &SEALContext::lastContextData)
        .def("key_context_data", &SEALContext::keyContextData)
        .def("first_parms_id", &SEALContext::firstParmsID)
        .def("last_parms_id", &SEALContext::lastParmsID)
        .def("key_parms_id", &SEALContext::keyParmsID)
        .def("using_keyswitching", &SEALContext::using_keyswitching)
        ;
    
    py::class_<Plaintext>(m, "Plaintext")
        .def(py::init<>())
        .def("set_zero", py::overload_cast<>(&Plaintext::setZero))
        .def("coeff_count", &Plaintext::coeffCount)
        .def("is_ntt_form", &Plaintext::isNttForm)
		.def("parms_id", py::overload_cast<>(&Plaintext::parmsID, py::const_), py::return_value_policy::reference)
        .def("set_parms_id", [](Plaintext& self, const ParmsID& p) {
            self.parmsID() = p;
        })
        .def("scale", py::overload_cast<>(&Plaintext::scale, py::const_))
        .def("set_scale", [](Plaintext& self, double s) {
            self.scale() = s;
        })
        .def("copy", [](const Plaintext& p) {
            return Plaintext(p);
        })
        .def("save", [](const Plaintext& p) {
            SAVE_MACRO
        })
        .def("load", [](Plaintext& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<Ciphertext>(m, "Ciphertext")
        .def(py::init<>())
        .def(py::init<const SEALContext&>())
        .def(py::init<const SEALContext&, ParmsID>())
        .def(py::init<const SEALContext&, ParmsID, size_t>())
        .def("correction_factor", py::overload_cast<>(&Ciphertext::correctionFactor, py::const_))
        .def("set_correction_factor", [](Ciphertext& self, uint64_t c) {
            self.correctionFactor() = c;
        })
        .def("resize", py::overload_cast<size_t>(&Ciphertext::resize))
        .def("reserve", py::overload_cast<size_t>(&Ciphertext::reserve))
		.def("parms_id", py::overload_cast<>(&Ciphertext::parmsID, py::const_), py::return_value_policy::reference)
        .def("set_parms_id", [](Ciphertext& self, const ParmsID& p) {
            self.parmsID() = p;
        })
        .def("scale", py::overload_cast<>(&Ciphertext::scale, py::const_))
        .def("set_scale", [](Ciphertext& self, double s) {
            self.scale() = s;
        })
        .def("is_ntt_form", py::overload_cast<>(&Ciphertext::isNttForm, py::const_))
        .def("coeff_modulus_size", &Ciphertext::coeffModulusSize)
        .def("poly_modulus_degree", &Ciphertext::polyModulusDegree)
        .def("copy", [](const Ciphertext& p) {
            return Ciphertext(p);
        })
        .def("save", [](const Ciphertext& p) {
            SAVE_MACRO
        })
        .def("load", [](Ciphertext& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<KeyGenerator>(m, "KeyGenerator")
        .def(py::init<const SEALContext&>())
        .def("secret_key", &KeyGenerator::secretKey)
        .def("create_public_key", py::overload_cast<PublicKey&>(
            &KeyGenerator::createPublicKey, py::const_
        ))
        .def("create_public_key", py::overload_cast<>(
            &KeyGenerator::createPublicKey, py::const_
        ))
        .def("create_relin_keys", py::overload_cast<RelinKeys&>(
            &KeyGenerator::createRelinKeys
        ))
        .def("create_relin_keys", py::overload_cast<>(
            &KeyGenerator::createRelinKeys
        ))
        .def("create_galois_keys", py::overload_cast<GaloisKeys&>(
            &KeyGenerator::createGaloisKeys
        ))
        .def("create_galois_keys", py::overload_cast<>(
            &KeyGenerator::createGaloisKeys
        ))
        .def("create_galois_keys", py::overload_cast<const vector<int>&, GaloisKeys&>(
            &KeyGenerator::createGaloisKeys
        ))
        .def("create_galois_keys", py::overload_cast<const vector<int>&, >(
            &KeyGenerator::createGaloisKeys
        ))
        ;

    py::class_<SecretKey>(m, "SecretKey")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&SecretKey::parmsID, py::const_))
        .def("save", [](const SecretKey& p) {
            SAVE_MACRO
        })
        .def("load", [](SecretKey& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<PublicKey>(m, "PublicKey")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&PublicKey::parmsID, py::const_))
        .def("save", [](const PublicKey& p) {
            SAVE_MACRO
        })
        .def("load", [](PublicKey& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<KSwitchKeys>(m, "KSwitchKeys")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&KSwitchKeys::parmsID, py::const_))
        .def("save", [](const KSwitchKeys& p) {
            SAVE_MACRO
        })
        .def("load", [](KSwitchKeys& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<RelinKeys>(m, "RelinKeys")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&RelinKeys::parmsID, py::const_))
        .def("save", [](const RelinKeys& p) {
            SAVE_MACRO
        })
        .def("load", [](RelinKeys& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<GaloisKeys>(m, "GaloisKeys")
        .def(py::init<>())
        .def("parms_id", py::overload_cast<>(&GaloisKeys::parmsID, py::const_))
        .def("save", [](const GaloisKeys& p) {
            SAVE_MACRO
        })
        .def("load", [](GaloisKeys& self, const py::bytes& str) {
            LOAD_MACRO
        })
        ;

    py::class_<BatchEncoder>(m, "BatchEncoder")
        .def(py::init<const SEALContext&>())
        .def("encode_int64", py::overload_cast<const vector<int64_t>&, Plaintext&>(&BatchEncoder::encode, py::const_))
        .def("encode", py::overload_cast<const vector<uint64_t>&, Plaintext&>(&BatchEncoder::encode, py::const_))
        .def("decode_int64", [](const BatchEncoder& self, const Plaintext& plain) {
            vector<int64_t> ret; self.decode(plain, ret); return ret;
        })
        .def("decode", [](const BatchEncoder& self, const Plaintext& plain) {
            vector<uint64_t> ret; self.decode(plain, ret); return ret;
        })
        .def("slot_count", &BatchEncoder::slotCount)
        ;

    py::class_<CKKSEncoder>(m, "CKKSEncoder")
        .def(py::init<const SEALContext&>())
        .def("encode", py::overload_cast<const vector<complex<double>>&, double, Plaintext&>(&CKKSEncoder::encode))
        .def("encode", py::overload_cast<const vector<complex<double>>&, ParmsID, double, Plaintext&>(&CKKSEncoder::encode))
        .def("decode", [](CKKSEncoder& self, const Plaintext& plain) {
            vector<complex<double>> ret; self.decode(plain, ret); return ret;
        })
        .def("slot_count", &CKKSEncoder::slotCount)
        ;

    py::class_<Encryptor>(m, "Encryptor")
        .def(py::init<const SEALContext&, const PublicKey&>())
        .def(py::init<const SEALContext&, const SecretKey&>())
        .def(py::init<const SEALContext&, const PublicKey&, const SecretKey&>())
        .def("set_public_key", &Encryptor::setPublicKey)
        .def("set_secret_key", &Encryptor::setSecretKey)
        .def("encrypt", py::overload_cast<const Plaintext&, Ciphertext&>(&Encryptor::encrypt, py::const_))
        .def("encrypt_zero", py::overload_cast<Ciphertext&>(&Encryptor::encryptZero, py::const_))
        .def("encrypt_zero", py::overload_cast<ParmsID, Ciphertext&>(&Encryptor::encryptZero, py::const_))
        .def("encrypt_symmetric", py::overload_cast<const Plaintext&, Ciphertext&>(&Encryptor::encryptSymmetric, py::const_))
        .def("encrypt_zero_symmetric", py::overload_cast<Ciphertext&>(&Encryptor::encryptZeroSymmetric, py::const_))
        .def("encrypt_zero_symmetric", py::overload_cast<ParmsID, Ciphertext&>(&Encryptor::encryptZeroSymmetric, py::const_))
        ;

    py::class_<Decryptor>(m, "Decryptor")
        .def(py::init<const SEALContext&, const SecretKey&>())
        .def("decrypt", &Decryptor::decrypt)
        ;

    py::class_<Evaluator>(m, "Evaluator")
        .def(py::init<const SEALContext&>())

        .def("negate_inplace",             &Evaluator::negateInplace)
        .def("negate",                     &Evaluator::negate)
        .def("add_inplace",                &Evaluator::addInplace)
        .def("add",                        &Evaluator::add)
        .def("add_many",                   &Evaluator::addMany)
        .def("sub_inplace",                &Evaluator::subInplace)
        .def("sub",                        &Evaluator::sub)
        .def("multiply_inplace",           &Evaluator::multiplyInplace)
        .def("multiply",                   &Evaluator::multiply)
        .def("square_inplace",             &Evaluator::squareInplace)
        .def("square",                     &Evaluator::square)
        .def("relinearize_inplace",        &Evaluator::relinearizeInplace)
        .def("relinearize",                &Evaluator::relinearize)

        .def("mod_switch_to_next_inplace", py::overload_cast<Ciphertext&>(
            &Evaluator::modSwitchToNextInplace, py::const_
        ))
        .def("mod_switch_to_next_inplace", py::overload_cast<Plaintext&>(
            &Evaluator::modSwitchToNextInplace, py::const_
        ))
        .def("mod_switch_to_next", py::overload_cast<const Ciphertext&, Ciphertext&>(
            &Evaluator::modSwitchToNext, py::const_
        ))
        .def("mod_switch_to_next", py::overload_cast<const Plaintext&, Plaintext&>(
            &Evaluator::modSwitchToNext, py::const_
        ))

        .def("mod_switch_to_inplace", py::overload_cast<Ciphertext&, ParmsID>(
            &Evaluator::modSwitchToInplace, py::const_
        ))
        .def("mod_switch_to_inplace", py::overload_cast<Plaintext&, ParmsID>(
            &Evaluator::modSwitchToInplace, py::const_
        ))
        .def("mod_switch_to", py::overload_cast<const Ciphertext&, ParmsID, Ciphertext&>(
            &Evaluator::modSwitchTo, py::const_
        ))
        .def("mod_switch_to", py::overload_cast<const Plaintext&, ParmsID, Plaintext&>(
            &Evaluator::modSwitchTo, py::const_
        ))

        .def("rescale_to_next_inplace", &Evaluator::rescaleToNextInplace)
        .def("rescale_to_next", &Evaluator::rescaleToNext)

        .def("rescale_to_inplace", &Evaluator::rescaleToInplace)
        .def("rescale_to", &Evaluator::rescaleTo)

        .def("multiply_many",          &Evaluator::multiplyMany)
        .def("exponentiate_inplace",   &Evaluator::exponentiateInplace)
        .def("exponentiate",           &Evaluator::exponentiate)
        .def("add_plain_inplace",      &Evaluator::addPlainInplace)
        .def("add_plain",              &Evaluator::addPlain)
        .def("sub_plain_inplace",      &Evaluator::subPlainInplace)
        .def("sub_plain",              &Evaluator::subPlain)
        .def("multiply_plain_inplace", &Evaluator::multiplyPlainInplace)
        .def("multiply_plain",         &Evaluator::multiplyPlain)

        .def("transform_to_ntt_inplace", py::overload_cast<Plaintext&, ParmsID>(
            &Evaluator::transformToNttInplace, py::const_
        ))
        .def("transform_to_ntt_inplace", py::overload_cast<Ciphertext&>(
            &Evaluator::transformToNttInplace, py::const_
        ))
        .def("transform_to_ntt", py::overload_cast<const Plaintext&, ParmsID, Plaintext&>(
            &Evaluator::transformToNtt, py::const_
        ))
        .def("transform_to_ntt", py::overload_cast<const Ciphertext&, Ciphertext&>(
            &Evaluator::transformToNtt, py::const_
        ))
        .def("transform_from_ntt_inplace", py::overload_cast<Ciphertext&>(
            &Evaluator::transformFromNttInplace, py::const_
        ))
        .def("transform_from_ntt", py::overload_cast<const Ciphertext&, Ciphertext&>(
            &Evaluator::transformFromNtt, py::const_
        ))

        .def("apply_galois_inplace", &Evaluator::applyGaloisInplace)
        .def("apply_galois", &Evaluator::applyGalois)
        .def("rotate_rows_inplace", &Evaluator::rotateRowsInplace)
        .def("rotate_rows", &Evaluator::rotateRows)
        .def("rotate_columns_inplace", &Evaluator::rotateColumnsInplace)
        .def("rotate_columns", &Evaluator::rotateColumns)
        .def("rotate_vector_inplace", &Evaluator::rotateVectorInplace)
        .def("rotate_vector", &Evaluator::rotateVector)
        .def("complex_conjugate_inplace", &Evaluator::complexConjugateInplace)
        .def("complex_conjugate", &Evaluator::complexConjugate)
        
        ;
    
}