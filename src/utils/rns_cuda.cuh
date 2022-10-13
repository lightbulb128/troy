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

            void decomposeArray(DevicePointer<uint64_t> value, size_t coeff_count) const;
            void composeArray(DevicePointer<uint64_t> value, size_t coeff_count) const;
            size_t size() const {return size_;}
            ConstDevicePointer<Modulus> base() const {return base_.asPointer();}
            ConstDevicePointer<MultiplyUIntModOperand> invPuncturedProdModBaseArray() const {
                return inv_punctured_prod_mod_base_array_.asPointer();
            }
            ConstDevicePointer<uint64_t> baseProd() const {
                return base_prod_.asPointer();
            }

        private:
            std::size_t size_;
            DeviceArray<Modulus> base_;
            DeviceArray<uint64_t> base_prod_;
            DeviceArray<uint64_t> punctured_prod_array_;
            DeviceArray<MultiplyUIntModOperand> inv_punctured_prod_mod_base_array_;
        };

        class BaseConverterCuda {
        public:
            BaseConverterCuda(const BaseConverter& copy):
                ibase_(copy.ibase_), obase_(copy.obase_) 
            {
                base_change_matrix_ = DeviceArray<uint64_t>(obase_.size() * ibase_.size());;
                size_t isize = ibase_.size();
                for (size_t i = 0; i < obase_.size(); i++) {
                    KernelProvider::copy<uint64_t>(
                        base_change_matrix_.get() + i * isize, 
                        copy.base_change_matrix_[i].get(), isize);
                }
            }
            void fastConvertArray(ConstDevicePointer<uint64_t> in, DevicePointer<uint64_t> out, size_t count) const;
            void exactConvertArray(ConstDevicePointer<uint64_t> in, DevicePointer<uint64_t> out, size_t count) const;
        private:
            RNSBaseCuda ibase_;
            RNSBaseCuda obase_;
            DeviceArray<uint64_t> base_change_matrix_; // obase_ * ibase_
        };

    }
}