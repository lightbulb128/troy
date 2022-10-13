#pragma once

#include "rns.h"
#include "devicearray.cuh"



namespace troy {
    namespace util {
        class RNSBaseCuda {
        public:
            RNSBaseCuda(const RNSBase& copy):
                size_(copy.size_),
                base_(copy.base_),
                base_prod_(copy.base_prod_),
                punctured_prod_array_(copy.punctured_prod_array_),
                inv_punctured_prod_mod_base_array_(copy.inv_punctured_prod_mod_base_array_)
            {}
            RNSBaseCuda(RNSBaseCuda&& move) = default;
            RNSBaseCuda(const RNSBaseCuda& copy) = default;

            void decomposeArray(DevicePointer<uint64_t> value, size_t poly_size, size_t coeff_count) const;
            void composeArray(DevicePointer<uint64_t> value, size_t poly_size, size_t coeff_count) const;

        private:
            std::size_t size_;
            DeviceArray<Modulus> base_;
            DeviceArray<uint64_t> base_prod_;
            DeviceArray<uint64_t> punctured_prod_array_;
            DeviceArray<MultiplyUIntModOperand> inv_punctured_prod_mod_base_array_;
        };
    }
}