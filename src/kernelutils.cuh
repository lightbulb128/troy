#pragma once

#include "kernelprovider.cuh"
#include "utils/devicearray.cuh"
#include "utils/hostarray.h"
#include "utils/uintarithsmallmod.h"
#include "modulus.h"

#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree

namespace troy {

    // static class. use as namespace
    class DeviceHelper {
    public:
        __device__ inline static uint64_t getModulusValue(const Modulus& m) {
            return m.value_;
        }
        __device__ inline static const uint64_t* getModulusConstRatio(const Modulus& m) {
            return static_cast<const uint64_t*>(&m.const_ratio_[0]);
        }
    };
    
    namespace kernel_util {

        using troy::util::ConstDevicePointer;
        using troy::util::DevicePointer;
        using CPointer = ConstDevicePointer<uint64_t>;
        using Pointer = DevicePointer<uint64_t>;
        using MPointer = ConstDevicePointer<Modulus>;
        using troy::util::MultiplyUIntModOperand;
        using uint128_t = unsigned __int128;

        inline util::DeviceArray<uint64_t> kAllocate(uint64_t s) {
            return util::DeviceArray<uint64_t>(s);
        }
        inline util::DeviceArray<uint64_t> kAllocate(uint64_t s, uint64_t t) {
            return util::DeviceArray<uint64_t>(s*t);
        }
        inline util::DeviceArray<uint64_t> kAllocate(uint64_t s, uint64_t t, uint64_t u) {
            return util::DeviceArray<uint64_t>(s*t*u);
        }

        inline util::DeviceArray<uint64_t> kAllocateZero(uint64_t s) {
            auto ret = util::DeviceArray<uint64_t>(s);
            KernelProvider::memsetZero(ret.get(), ret.size());
            return ret;
        }
        inline util::DeviceArray<uint64_t> kAllocateZero(uint64_t s, uint64_t t) {
            auto ret = util::DeviceArray<uint64_t>(s*t);
            KernelProvider::memsetZero(ret.get(), ret.size());
            return ret;
        }
        inline util::DeviceArray<uint64_t> kAllocateZero(uint64_t s, uint64_t t, uint64_t u) {
            auto ret = util::DeviceArray<uint64_t>(s*t*u);
            KernelProvider::memsetZero(ret.get(), ret.size());
            return ret;
        }
        











        inline size_t ceilDiv_(size_t a, size_t b) {
            return (a%b) ? (a/b+1) : (a/b); 
        }

        __device__ inline unsigned char dAddUint64(uint64_t operand1, uint64_t operand2, uint64_t* result) {
            *result = operand1 + operand2;
            return static_cast<unsigned char>(*result < operand1);
        }


        __device__ inline void dMultiplyUint64HW64(uint64_t operand1, uint64_t operand2, uint64_t *hw64) {                                                         
            *hw64 = static_cast<uint64_t>( 
                ((static_cast<uint128_t>(operand1) * static_cast<uint128_t>(operand2)) >> 64)); 
        }

        __device__ inline uint64_t dBarrettReduce64(uint64_t input, const Modulus& modulus) {
            uint64_t tmp[2];
            const std::uint64_t *const_ratio = DeviceHelper::getModulusConstRatio(modulus);
            dMultiplyUint64HW64(input, const_ratio[1], tmp + 1);
            uint64_t modulusValue = DeviceHelper::getModulusValue(modulus);

            // Barrett subtraction
            tmp[0] = input - tmp[1] * modulusValue;

            // One more subtraction is enough
            return (tmp[0] >= modulusValue) ? (tmp[0] - modulusValue) : (tmp[0]);
        }
        

        __device__ inline void dMultiplyUint64(uint64_t operand1, uint64_t operand2, uint64_t *result128)
        {        
            uint128_t product = static_cast<uint128_t>(operand1) * operand2; 
            result128[0] = static_cast<unsigned long long>(product);         
            result128[1] = static_cast<unsigned long long>(product >> 64); 
        }

        __device__ inline uint64_t dMultiplyUintMod(uint64_t x, const MultiplyUIntModOperand& y, const Modulus& modulus) {
            uint64_t tmp1, tmp2;
            const std::uint64_t p = DeviceHelper::getModulusValue(modulus);
            dMultiplyUint64HW64(x, y.quotient, &tmp1);
            tmp2 = y.operand * x - tmp1 * p;
            return (tmp2 >= p) ? (tmp2 - p) : (tmp2);
        }
        
        __device__ inline void dDivideUint128Inplace(uint64_t *numerator, uint64_t denominator, uint64_t *quotient)
        {        
            uint128_t n, q;                                                                            
            n = (static_cast<uint128_t>(numerator[1]) << 64) | (static_cast<uint128_t>(numerator[0])); 
            q = n / denominator;                                                                       
            n -= q * denominator;                                                                      
            numerator[0] = static_cast<std::uint64_t>(n);                                              
            numerator[1] = 0;                                                                          
            quotient[0] = static_cast<std::uint64_t>(q);                                                 
            quotient[1] = static_cast<std::uint64_t>(q >> 64);     
        }
        
        __device__ inline unsigned char dSubUint64(uint64_t operand1, uint64_t operand2, uint64_t* result) {
            *result = operand1 - operand2;
            return static_cast<unsigned char>(operand2 > operand1);
        }










        
        
        __global__ void gAddPolyCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* modulus,
            uint64_t* result
        );

        void kAddPolyCoeffmod(
            CPointer operand1,
            CPointer operand2,
            POLY_ARRAY_ARGUMENTS,
            MPointer modulus,
            Pointer result
        );

        __global__ void gDyadicConvolutionCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2_reversed,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* moduli,
            uint64_t* single_poly_result_accumulator
        );

        void kDyadicConvolutionCoeffmod(
            CPointer operand1,
            CPointer operand2_reversed,
            POLY_ARRAY_ARGUMENTS,
            MPointer moduli,
            Pointer single_poly_result_accumulator
        );

        __global__ void gDyadicSquareCoeffmod(
            uint64_t* operand,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            const Modulus* moduli
        );

        void kDyadicSquareCoeffmod(
            Pointer operand,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            MPointer moduli
        );
        
        __global__ void gMultiplyPolyScalarCoeffmod(
            const uint64_t* poly_array,
            POLY_ARRAY_ARGUMENTS,
            const MultiplyUIntModOperand* reduced_scalar,
            const Modulus* modulus,
            uint64_t* result);

        void kMultiplyPolyScalarCoeffmod(
            CPointer poly_array, POLY_ARRAY_ARGUMENTS, 
            uint64_t scalar, MPointer modulus, Pointer result);

        __global__ void gNegatePolyCoeffmod(
            const uint64_t* poly_array,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* modulus,
            uint64_t *result
        );

        void kNegatePolyCoeffmod(
            CPointer poly_array, POLY_ARRAY_ARGUMENTS,
            MPointer modulus, Pointer result
        );

        __global__ void gSetMultiplyUIntModOperand(
            uint64_t scalar, const Modulus* moduli, size_t n,
            MultiplyUIntModOperand* result);

        
        void kSetPolyArray(
            CPointer poly, POLY_ARRAY_ARGUMENTS, Pointer result
        );
        
        __global__ void gSubPolyCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* modulus,
            uint64_t* result
        );

        void kSubPolyCoeffmod(
            CPointer operand1,
            CPointer operand2,
            POLY_ARRAY_ARGUMENTS,
            MPointer modulus,
            Pointer result
        );

    }
}
