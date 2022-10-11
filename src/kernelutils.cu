#include "kernelutils.cuh"

#define KERNEL_CALL(funcname, n) size_t block_count = ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

namespace troy {
    
    // static class. use as namespace
    class DeviceHelper {
    public:
        __device__ static uint64_t getModulusValue(const Modulus& m) {
            return m.value_;
        }
        __device__ static const uint64_t* getModulusConstRatio(const Modulus& m) {
            return static_cast<const uint64_t*>(&m.const_ratio_[0]);
        }
    };

    namespace kernel_util {

        // using troy::util::ConstDevicePointer;
        // using troy::util::DevicePointer;
        // using CPointer = ConstDevicePointer<uint64_t>;
        // using Pointer = DevicePointer<uint64_t>;
        // using MPointer = ConstDevicePointer<Modulus>;
        // using troy::util::MultiplyUIntModOperand;
        // using uint128_t = unsigned __int128;
        
        __device__ void dMultiplyUint64HW64(uint64_t operand1, uint64_t operand2, uint64_t *hw64) {                                                         
            *hw64 = static_cast<uint64_t>( 
                ((static_cast<uint128_t>(operand1) * static_cast<uint128_t>(operand2)) >> 64)); 
        }

        __device__ uint64_t dMultiplyUintMod(uint64_t x, const MultiplyUIntModOperand& y, const Modulus& modulus) {
            uint64_t tmp1, tmp2;
            const std::uint64_t p = DeviceHelper::getModulusValue(modulus);
            dMultiplyUint64HW64(x, y.quotient, &tmp1);
            tmp2 = y.operand * x - tmp1 * p;
            return (tmp2 >= p) ? (tmp2 - p) : (tmp2);
        }

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

        __device__ uint64_t dBarrettReduce64(uint64_t input, const Modulus& modulus) {
            uint64_t tmp[2];
            const std::uint64_t *const_ratio = DeviceHelper::getModulusConstRatio(modulus);
            dMultiplyUint64HW64(input, const_ratio[1], tmp + 1);
            uint64_t modulusValue = DeviceHelper::getModulusValue(modulus);

            // Barrett subtraction
            tmp[0] = input - tmp[1] * modulusValue;

            // One more subtraction is enough
            return (tmp[0] >= modulusValue) ? (tmp[0] - modulusValue) : (tmp[0]);
        }

        __global__ void gMultiplyPolyScalarCoeffmod(
            const uint64_t* poly_array,
            POLY_ARRAY_ARGUMENTS,
            const MultiplyUIntModOperand* reduced_scalar,
            const Modulus* modulus,
            uint64_t* result)
        {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(poly_index, poly_size) {
                FOR_N(rns_index, coeff_modulus_size) {
                    size_t id = (poly_index * coeff_modulus_size + rns_index) * poly_modulus_degree;
                    result[id] = dMultiplyUintMod(poly_array[id], reduced_scalar[rns_index], modulus[rns_index]);
                }
            }
        }

        
        __device__ void dDivideUint128Inplace(uint64_t *numerator, uint64_t denominator, uint64_t *quotient)
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

        __global__ void gSetMultiplyUIntModOperand(uint64_t scalar, const Modulus* moduli, size_t n, MultiplyUIntModOperand* result) {
            GET_INDEX_COND_RETURN(n);
            uint64_t reduced = dBarrettReduce64(scalar, moduli[gindex]);
            result[gindex].operand = reduced;
            std::uint64_t wide_quotient[2]{ 0, 0 };
            std::uint64_t wide_coeff[2]{ 0, result[gindex].operand };
            dDivideUint128Inplace(wide_coeff, DeviceHelper::getModulusValue(moduli[gindex]), wide_quotient);
            result[gindex].quotient = wide_quotient[0];
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

        
        void kSetPolyArray(
            CPointer poly, POLY_ARRAY_ARGUMENTS, Pointer result
        ) {
            KernelProvider::copyOnDevice(
                result.get(), poly.get(), 
                poly_size * coeff_modulus_size * poly_modulus_degree
            );
        }
        



    }
}