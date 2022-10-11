#pragma once

#include <iostream>
#include "utils/devicearray.cuh"
#include "ciphertext.h"
#include "context_cuda.cuh"

namespace troy {

    class CiphertextCuda {

    public:
        
        using ct_coeff_type = std::uint64_t;

        CiphertextCuda(): data_() {}

        CiphertextCuda(const Ciphertext& host):
            parms_id_(host.parms_id_),
            is_ntt_form_(host.is_ntt_form_),
            size_(host.size_),
            poly_modulus_degree_(host.poly_modulus_degree_),
            coeff_modulus_size_(host.coeff_modulus_size_),
            scale_(host.scale_),
            correction_factor_(host.correction_factor_),
            data_(host.data_) {}

        Ciphertext cpu() {
            Ciphertext ret;
            ret.parms_id_ = parms_id_;
            ret.is_ntt_form_ = is_ntt_form_;
            ret.size_ = size_;
            ret.poly_modulus_degree_ = poly_modulus_degree_;
            ret.coeff_modulus_size_ = coeff_modulus_size_;
            ret.scale_ = scale_;
            ret.correction_factor_ = correction_factor_;
            ret.data_ = data_.toHost();
            return ret;
        }

        inline uint64_t& correctionFactor() noexcept 
            {return correction_factor_;}
        inline const uint64_t& correctionFactor() const noexcept 
            {return correction_factor_;}
        inline size_t size() const noexcept {return size_;}
        inline util::DevicePointer<uint64_t> data() {return data_.asPointer();}
        inline util::ConstDevicePointer<uint64_t> data() const {return data_.asPointer();}
        inline util::DevicePointer<uint64_t> data(size_t i) {
            return data_.asPointer() + coeff_modulus_size_ * poly_modulus_degree_ * i;
        }
        inline util::ConstDevicePointer<uint64_t> data(size_t i) const {
            return data_.asPointer() + coeff_modulus_size_ * poly_modulus_degree_ * i;
        }
        inline void resize(const SEALContextCuda& context, ParmsID parms_id, size_t size) {
            auto context_data_ptr = context.getContextData(parms_id);
            if (!context_data_ptr) 
                throw std::invalid_argument("parms_id is not valid for encryption parameters");
            auto &parms = context_data_ptr->parms();
            parms_id_ = context_data_ptr->parmsID();
            resizeInternal(size, parms.polyModulusDegree(), parms.coeffModulus().size());
        }
        inline ParmsID& parmsID() noexcept {return parms_id_;}
        inline const ParmsID& parmsID() const noexcept {return parms_id_;}
        
    private:

        void resizeInternal(size_t size, size_t poly_modulus_degree, size_t coeff_modulus_size) {
            if ((size < SEAL_CIPHERTEXT_SIZE_MIN && size != 0) || size > SEAL_CIPHERTEXT_SIZE_MAX)
            {
                throw std::invalid_argument("invalid size");
            }
            size_t new_data_size = size * poly_modulus_degree * coeff_modulus_size;
            data_.resize(new_data_size);
            size_ = size;
            poly_modulus_degree_ = poly_modulus_degree;
            coeff_modulus_size_ = coeff_modulus_size;
        }

        ParmsID parms_id_ = parmsIDZero;

        bool is_ntt_form_ = false;

        std::size_t size_ = 0;

        std::size_t poly_modulus_degree_ = 0;

        std::size_t coeff_modulus_size_ = 0;

        double scale_ = 1.0;

        std::uint64_t correction_factor_ = 1;

        util::DeviceDynamicArray<ct_coeff_type> data_;
    };

}