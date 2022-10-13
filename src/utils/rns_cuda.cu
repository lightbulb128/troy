#include "rns_cuda.cuh"
#include "../kernelutils.cuh"

#define KERNEL_CALL(funcname, n) size_t block_count = kernel_util::ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

namespace troy {

    namespace util {

        __global__ void gDecomposeArray(
            const uint64_t* values, POLY_ARRAY_ARGUMENTS, const Modulus* moduli,
            uint64_t* result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(rns_index, coeff_modulus_size) {
                FOR_N(poly_index, poly_size) {
                    size_t oid = poly_index * coeff_modulus_size * poly_modulus_degree + gindex * coeff_modulus_size;
                    size_t nid = poly_index * coeff_modulus_size * poly_modulus_degree + rns_index * poly_modulus_degree + gindex;
                    result[nid] = kernel_util::dModuloUint(values + oid, coeff_modulus_size, moduli[rns_index]);
                }
            }
        } 

        // temp should be at least coeff_modulus_size * poly_modulus_degree large
        __global__ void gComposeArray(
            const uint64_t* value, POLY_ARRAY_ARGUMENTS, const Modulus* moduli,
            const uint64_t* base_prod,
            const uint64_t* punctured_prod_array,
            const MultiplyUIntModOperand* inv_punctured_prod_mod_base_array,
            uint64_t* temp, uint64_t* result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            uint64_t* temp_target = temp + gindex * coeff_modulus_size;
            size_t d = poly_modulus_degree * coeff_modulus_size;
            FOR_N(poly_index, poly_size) {
                FOR_N(rns_index, coeff_modulus_size) temp_target[rns_index] = 0;
                FOR_N(rns_index, coeff_modulus_size) {
                    uint64_t temp_prod = kernel_util::dMultiplyUintMod(
                        value[poly_index * d + rns_index * poly_modulus_degree + gindex],
                        inv_punctured_prod_mod_base_array[rns_index], moduli[rns_index]);
                    kernel_util::dMultiplyUint(
                        punctured_prod_array + rns_index * coeff_modulus_size, 
                        coeff_modulus_size, temp_prod, coeff_modulus_size, temp_target);
                    kernel_util::dAddUintUintMod(temp_target, 
                        result + d * poly_index + gindex * coeff_modulus_size, 
                        base_prod, coeff_modulus_size, result + d * poly_index + gindex * coeff_modulus_size);
                }
            }
        }

        void RNSBaseCuda::decomposeArray(DevicePointer<uint64_t> values, size_t poly_size, size_t coeff_count) const {
            if (size_ <= 1) return;
            // FIXME: temporary array -> rns base. could use dynamic array
            DeviceArray<uint64_t> copy(poly_size * size_ * coeff_count);
            KernelProvider::copyOnDevice(copy.get(), values.get(), poly_size * size_ * coeff_count);
            KERNEL_CALL(gDecomposeArray, coeff_count)(
                copy.get(), poly_size, size_, coeff_count, base_.get(), values.get()
            );
        }

        void RNSBaseCuda::composeArray(DevicePointer<uint64_t> values, size_t poly_size, size_t coeff_count) const {
            if (size_ <= 1) return;
            // FIXME: temporary array -> rns base. could use dynamic array
            DeviceArray<uint64_t> copy(poly_size * size_ * coeff_count);
            DeviceArray<uint64_t> temp(size_ * coeff_count);
            KernelProvider::copyOnDevice(copy.get(), values.get(), poly_size * size_ * coeff_count);
            KernelProvider::memsetZero<uint64_t>(values.get(), poly_size * size_ * coeff_count);
            KERNEL_CALL(gComposeArray, coeff_count)(
                copy.get(), poly_size, size_, coeff_count,
                base_.get(), base_prod_.get(), punctured_prod_array_.get(),
                inv_punctured_prod_mod_base_array_.get(), temp.get(), values.get()
            );
        }

    }

}