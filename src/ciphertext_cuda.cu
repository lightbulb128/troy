#include "ciphertext_cuda.cuh"
#include "serialize.h"
#include "utils/rlwe_cuda.cuh"

namespace troy {

    void CiphertextCuda::save(std::ostream& stream) const {
        savet(stream, &parms_id_);
        savet(stream, &is_ntt_form_);
        savet(stream, &size_);
        savet(stream, &poly_modulus_degree_);
        savet(stream, &coeff_modulus_size_);
        savet(stream, &scale_);
        savet(stream, &correction_factor_);
        savet(stream, &seed_);
        if (seed_ != 0 && size_ > 2) {
            throw std::invalid_argument("Seed exists but size is not 2.");
        }
        if (seed_ != 0) {
            util::HostArray<uint64_t> r(poly_modulus_degree_ * coeff_modulus_size_);
            KernelProvider::retrieve(r.get(), data_.get(), r.size());
            size_t dataSize = r.size();
            savet(stream, &dataSize);
            stream.write(reinterpret_cast<char*>(r.get()), sizeof(CiphertextCuda::ct_coeff_type) * r.size());
        } else {
            auto r = data_.toHost();
            size_t dataSize = r.size();
            savet(stream, &dataSize);
            stream.write(reinterpret_cast<char*>(r.begin()), sizeof(CiphertextCuda::ct_coeff_type) * r.size());
        }
    }

    void CiphertextCuda::load(std::istream& stream) {
        seed_ = 0;
        loadt(stream, &parms_id_);
        loadt(stream, &is_ntt_form_);
        loadt(stream, &size_);
        loadt(stream, &poly_modulus_degree_);
        loadt(stream, &coeff_modulus_size_);
        loadt(stream, &scale_);
        loadt(stream, &correction_factor_);
        uint64_t seed; loadt(stream, &seed);
        if (seed == 0) {
            size_t dataSize;
            loadt(stream, &dataSize);
            util::HostArray<ct_coeff_type> host(dataSize);
            stream.read(reinterpret_cast<char*>(host.get()), dataSize * sizeof(ct_coeff_type));
            data_.ensure(host.size());
            KernelProvider::copy(data_.get(), host.get(), dataSize);
        } else {
            throw std::invalid_argument("seed is not zero.");
        }
    }

    void CiphertextCuda::load(std::istream& stream, const SEALContextCuda& context) {
        seed_ = 0;
        loadt(stream, &parms_id_);
        loadt(stream, &is_ntt_form_);
        loadt(stream, &size_);
        loadt(stream, &poly_modulus_degree_);
        loadt(stream, &coeff_modulus_size_);
        loadt(stream, &scale_);
        loadt(stream, &correction_factor_);
        uint64_t seed; loadt(stream, &seed);
        if (seed == 0) {
            size_t dataSize;
            loadt(stream, &dataSize);
            util::HostArray<ct_coeff_type> host(dataSize);
            stream.read(reinterpret_cast<char*>(host.get()), dataSize * sizeof(ct_coeff_type));
            data_.ensure(host.size());
            KernelProvider::copy(data_.get(), host.get(), dataSize);
        } else {
            if (size_ > 2) throw std::invalid_argument("Seed exists but size is not 2.");
            size_t dataSize;
            loadt(stream, &dataSize);
            util::HostArray<ct_coeff_type> host(dataSize);
            stream.read(reinterpret_cast<char*>(host.get()), dataSize * sizeof(ct_coeff_type));
            data_.ensure(2 * poly_modulus_degree_ * coeff_modulus_size_);
            KernelProvider::copy(data_.get(), host.get(), dataSize);
            util::DeviceArray<curandState> curandStates(poly_modulus_degree_ * coeff_modulus_size_);
            auto& modulus = context.getContextData(parms_id_)->parms().coeffModulus();
            util::sampler::setupCurandStates(curandStates.get(), poly_modulus_degree_, seed);
            util::sampler::kSamplePolyUniform(curandStates.get(), modulus.size(), poly_modulus_degree_, modulus, data(1));
        }
    }

}