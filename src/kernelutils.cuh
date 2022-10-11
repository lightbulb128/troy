#pragma once

#include "kernelprovider.cuh"
#include "utils/devicearray.cuh"
#include "utils/hostarray.h"
#include "utils/uintarithsmallmod.h"
#include "modulus.h"

#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree

namespace troy {
    
    namespace kernel_util {

        using troy::util::ConstDevicePointer;
        using troy::util::DevicePointer;
        using CPointer = ConstDevicePointer<uint64_t>;
        using Pointer = DevicePointer<uint64_t>;
        using MPointer = ConstDevicePointer<Modulus>;
        using troy::util::MultiplyUIntModOperand;
        using uint128_t = unsigned __int128;

        inline size_t ceilDiv_(size_t a, size_t b) {
            return (a%b) ? (a/b+1) : (a/b); 
        }
        
        __device__ void dMultiplyUint64HW64(
            uint64_t operand1, uint64_t operand2, uint64_t *hw64);

        __device__ uint64_t dMultiplyUintMod(
            uint64_t x, const MultiplyUIntModOperand& y, const Modulus& modulus);

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

        __device__ uint64_t dBarrettReduce64(
            uint64_t input, const Modulus& modulus);

        __global__ void gMultiplyPolyScalarCoeffmod(
            const uint64_t* poly_array,
            POLY_ARRAY_ARGUMENTS,
            const MultiplyUIntModOperand* reduced_scalar,
            const Modulus* modulus,
            uint64_t* result);

        
        __device__ void dDivideUint128Inplace(
            uint64_t *numerator, uint64_t denominator, uint64_t *quotient);

        __global__ void gSetMultiplyUIntModOperand(
            uint64_t scalar, const Modulus* moduli, size_t n,
            MultiplyUIntModOperand* result);

        void kMultiplyPolyScalarCoeffmod(
            CPointer poly_array, POLY_ARRAY_ARGUMENTS, 
            uint64_t scalar, MPointer modulus, Pointer result);

        
        void kSetPolyArray(
            CPointer poly, POLY_ARRAY_ARGUMENTS, Pointer result
        );
        

    }
}
