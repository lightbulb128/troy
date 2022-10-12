#include "kernelutils.cuh"

#define KERNEL_CALL(funcname, n) size_t block_count = ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

namespace troy {

    namespace kernel_util {

        // using troy::util::ConstDevicePointer;
        // using troy::util::DevicePointer;
        // using CPointer = ConstDevicePointer<uint64_t>;
        // using Pointer = DevicePointer<uint64_t>;
        // using MPointer = ConstDevicePointer<Modulus>;
        // using troy::util::MultiplyUIntModOperand;
        // using uint128_t = unsigned __int128;






        


        __global__ void gAddPolyCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* modulus,
            uint64_t* result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(rns_index, coeff_modulus_size) {
                const uint64_t modulusValue = DeviceHelper::getModulusValue(modulus[rns_index]);
                FOR_N(poly_index, poly_size) {
                    size_t id = (poly_index * coeff_modulus_size + rns_index) * poly_modulus_degree + gindex;
                    uint64_t sum = operand1[id] + operand2[id];
                    result[id] = sum >= modulusValue ? sum - modulusValue : sum;
                }
            }
        }

        void kAddPolyCoeffmod(
            CPointer operand1,
            CPointer operand2,
            POLY_ARRAY_ARGUMENTS,
            MPointer modulus,
            Pointer result
        ) {
            KERNEL_CALL(gAddPolyCoeffmod, poly_modulus_degree)(
                operand1.get(), operand2.get(),
                POLY_ARRAY_ARGCALL, modulus.get(), result.get()
            );
        }

        __device__ inline uint64_t dDyadicSingle(uint64_t o1, uint64_t o2, uint64_t modulus_value, uint64_t const_ratio_0, uint64_t const_ratio_1) {
            
            uint64_t z[2], tmp1, tmp2[2], tmp3, carry;
            
            // Reduces z using base 2^64 Barrett reduction
            dMultiplyUint64(o1, o2, z);

            // Multiply input and const_ratio
            // Round 1
            dMultiplyUint64HW64(z[0], const_ratio_0, &carry);
            dMultiplyUint64(z[0], const_ratio_1, tmp2);
            tmp3 = tmp2[1] + dAddUint64(tmp2[0], carry, &tmp1);

            // Round 2
            dMultiplyUint64(z[1], const_ratio_0, tmp2);
            carry = tmp2[1] + dAddUint64(tmp1, tmp2[0], &tmp1);

            // This is all we care about
            tmp1 = z[1] * const_ratio_1 + tmp3 + carry;

            // Barrett subtraction
            tmp3 = z[0] - tmp1 * modulus_value;

            // Claim: One more subtraction is enough
            uint64_t sum = ((tmp3 >= modulus_value) ? (tmp3 - modulus_value) : (tmp3));
            uint64_t res = sum >= modulus_value ? sum-modulus_value : sum;
            return res;
        }

        __global__ void gDyadicConvolutionCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2_reversed,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* moduli,
            uint64_t* single_poly_result_accumulator
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(rns_index, coeff_modulus_size) {
                const uint64_t modulus_value = DeviceHelper::getModulusValue(moduli[rns_index]);
                const uint64_t const_ratio_0 = DeviceHelper::getModulusConstRatio(moduli[rns_index])[0];
                const uint64_t const_ratio_1 = DeviceHelper::getModulusConstRatio(moduli[rns_index])[1];
                FOR_N(poly_index, poly_size) {

                    const uint64_t* o1 = operand1 
                        + (poly_index * coeff_modulus_size + rns_index) * poly_modulus_degree + gindex;
                    const uint64_t* o2 = operand2_reversed - poly_index * coeff_modulus_size * poly_modulus_degree
                        + rns_index * poly_modulus_degree + gindex;
                    uint64_t* res = single_poly_result_accumulator
                        + rns_index * poly_modulus_degree + gindex;
                    
                    // Claim: One more subtraction is enough
                    uint64_t sum = *res + dDyadicSingle(*o1, *o2, modulus_value, const_ratio_0, const_ratio_1);
                    *res = sum >= modulus_value ? sum-modulus_value : sum;
                }
            }
        }

        void kDyadicConvolutionCoeffmod(
            CPointer operand1,
            CPointer operand2_reversed,
            POLY_ARRAY_ARGUMENTS,
            MPointer moduli,
            Pointer single_poly_result_accumulator
        ) {
            KERNEL_CALL(gDyadicConvolutionCoeffmod, poly_modulus_degree) (
                operand1.get(), 
                operand2_reversed.get(), 
                POLY_ARRAY_ARGCALL,
                moduli.get(), single_poly_result_accumulator.get()
            );
        }

        __global__ void gDyadicSquareCoeffmod(
            uint64_t* operand,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            const Modulus* moduli
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            size_t d = coeff_modulus_size * poly_modulus_degree;
            FOR_N(rns_index, coeff_modulus_size) {
                const uint64_t modulus_value = DeviceHelper::getModulusValue(moduli[rns_index]);
                const uint64_t const_ratio_0 = DeviceHelper::getModulusConstRatio(moduli[rns_index])[0];
                const uint64_t const_ratio_1 = DeviceHelper::getModulusConstRatio(moduli[rns_index])[1];
                size_t id = rns_index * poly_modulus_degree + gindex;
                operand[2 * d + id] = dDyadicSingle(operand[1 * d + id], operand[1 * d + id], modulus_value, const_ratio_0, const_ratio_1);
                uint64_t cross = dDyadicSingle(operand[0 * d + id], operand[1 * d + id], modulus_value, const_ratio_0, const_ratio_1);
                cross += cross;
                operand[1 * d + id] = cross >= modulus_value ? cross-modulus_value : cross;
                operand[0 * d + id] = dDyadicSingle(operand[0 * d + id], operand[0 * d + id], modulus_value, const_ratio_0, const_ratio_1);
            }
        }

        void kDyadicSquareCoeffmod(
            Pointer operand,
            size_t coeff_modulus_size,
            size_t poly_modulus_degree,
            MPointer moduli
        ) {
            KERNEL_CALL(gDyadicSquareCoeffmod, poly_modulus_degree)(
                operand.get(), coeff_modulus_size, poly_modulus_degree,
                moduli.get()
            );
        }


        __global__ void gMultiplyPolyScalarCoeffmod(
            const uint64_t* poly_array,
            POLY_ARRAY_ARGUMENTS,
            const MultiplyUIntModOperand* reduced_scalar,
            const Modulus* modulus,
            uint64_t* result)
        {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(rns_index, coeff_modulus_size) {
                FOR_N(poly_index, poly_size) {
                    size_t id = (poly_index * coeff_modulus_size + rns_index) * poly_modulus_degree;
                    result[id] = dMultiplyUintMod(poly_array[id], reduced_scalar[rns_index], modulus[rns_index]);
                }
            }
        }


        void kMultiplyPolyScalarCoeffmod(CPointer poly_array, POLY_ARRAY_ARGUMENTS, uint64_t scalar, MPointer modulus, Pointer result)
        {
            util::DeviceArray<MultiplyUIntModOperand> reduced_scalar(coeff_modulus_size);
            assert(coeff_modulus_size <= 256);
            gSetMultiplyUIntModOperand<<<1, coeff_modulus_size>>>(scalar, modulus.get(), coeff_modulus_size, reduced_scalar.get());
            KERNEL_CALL(gMultiplyPolyScalarCoeffmod, poly_modulus_degree)(
                poly_array.get(), POLY_ARRAY_ARGCALL, reduced_scalar.get(), 
                modulus.get(), result.get()
            ); 
        }

        __global__ void gNegatePolyCoeffmod(
            const uint64_t* poly_array,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* modulus,
            uint64_t *result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(rns_index, coeff_modulus_size) {
                auto modulus_value = DeviceHelper::getModulusValue(modulus[rns_index]);
                FOR_N(poly_index, poly_size) {
                    size_t id = (poly_index * coeff_modulus_size + rns_index) * poly_modulus_degree + gindex;
                    uint64_t coeff = poly_array[id];
                    int64_t non_zero = (coeff != 0);
                    result[id] = (modulus_value - coeff) & static_cast<uint64_t>(-non_zero);
                }
            }
        }

        void kNegatePolyCoeffmod(
            CPointer poly_array, POLY_ARRAY_ARGUMENTS,
            MPointer modulus, Pointer result
        ) {
            KERNEL_CALL(gNegatePolyCoeffmod, poly_modulus_degree)(
                poly_array.get(),
                POLY_ARRAY_ARGCALL,
                modulus.get(),
                result.get()
            );
        }

        __global__ void gSetMultiplyUIntModOperand(uint64_t scalar, const Modulus* moduli, size_t n, MultiplyUIntModOperand* result) {
            GET_INDEX_COND_RETURN(n);
            uint64_t reduced = dBarrettReduce64(scalar, moduli[gindex]);
            result[gindex].operand = reduced;
            std::uint64_t wide_quotient[2]{ 0, 0 };
            std::uint64_t wide_coeff[2]{ 0, result[gindex].operand };
            dDivideUint128Inplace(wide_coeff, DeviceHelper::getModulusValue(moduli[gindex]), wide_quotient);
            result[gindex].quotient = wide_quotient[0];
        }

        
        void kSetPolyArray(
            CPointer poly, POLY_ARRAY_ARGUMENTS, Pointer result
        ) {
            KernelProvider::copyOnDevice(
                result.get(), poly.get(), 
                poly_size * coeff_modulus_size * poly_modulus_degree
            );
        }

        __global__ void gSubPolyCoeffmod(
            const uint64_t* operand1,
            const uint64_t* operand2,
            POLY_ARRAY_ARGUMENTS,
            const Modulus* modulus,
            uint64_t* result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(rns_index, coeff_modulus_size) {
                const uint64_t modulusValue = DeviceHelper::getModulusValue(modulus[rns_index]);
                FOR_N(poly_index, poly_size) {
                    size_t id = (poly_index * coeff_modulus_size + rns_index) * poly_modulus_degree + gindex;
                    uint64_t temp_result;
                    int64_t borrow = dSubUint64(operand1[id], operand2[id], &temp_result);
                    result[id] = temp_result + (modulusValue & static_cast<std::uint64_t>(-borrow));
                }
            }
        }

        void kSubPolyCoeffmod(
            CPointer operand1,
            CPointer operand2,
            POLY_ARRAY_ARGUMENTS,
            MPointer modulus,
            Pointer result
        ) {
            KERNEL_CALL(gSubPolyCoeffmod, poly_modulus_degree)(
                operand1.get(), operand2.get(),
                POLY_ARRAY_ARGCALL, modulus.get(), result.get()
            );
        }


    }
}