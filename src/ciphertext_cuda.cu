#include "ciphertext_cuda.cuh"
#include "serialize.h"

namespace troy {

    void CiphertextCuda::save(std::ostream& stream) const {
        savet(stream, &parms_id_);
        savet(stream, &is_ntt_form_);
        savet(stream, &size_);
        savet(stream, &poly_modulus_degree_);
        savet(stream, &coeff_modulus_size_);
        savet(stream, &scale_);
        savet(stream, &correction_factor_);
        auto r = data_.toHost();
        size_t dataSize = r.size();
        savet(stream, &dataSize);
        stream.write(reinterpret_cast<char*>(r.begin()), sizeof(CiphertextCuda::ct_coeff_type) * r.size());
    }

    void CiphertextCuda::load(std::istream& stream) {
        loadt(stream, &parms_id_);
        loadt(stream, &is_ntt_form_);
        loadt(stream, &size_);
        loadt(stream, &poly_modulus_degree_);
        loadt(stream, &coeff_modulus_size_);
        loadt(stream, &scale_);
        loadt(stream, &correction_factor_);
        size_t dataSize;
        loadt(stream, &dataSize);
        util::HostArray<ct_coeff_type> host(dataSize);
        stream.read(reinterpret_cast<char*>(host.get()), dataSize * sizeof(ct_coeff_type));
        data_.ensure(host.size());
        KernelProvider::copy(data_.get(), host.get(), dataSize);
    }

}