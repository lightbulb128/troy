#include "rns_cuda.cuh"
#include "../kernelutils.cuh"

#define KERNEL_CALL(funcname, n) size_t block_count = kernel_util::ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define POLY_ARGUMENTS size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARGCALL coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

namespace troy {

    namespace util {

        __global__ void gDecomposeArray(
            const uint64_t* values, POLY_ARGUMENTS, const Modulus* moduli,
            uint64_t* result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            FOR_N(rns_index, coeff_modulus_size) {
                size_t oid = gindex * coeff_modulus_size;
                size_t nid = rns_index * poly_modulus_degree + gindex;
                result[nid] = kernel_util::dModuloUint(values + oid, coeff_modulus_size, moduli[rns_index]);
            }
        } 

        // temp should be at least coeff_modulus_size * poly_modulus_degree large
        __global__ void gComposeArray(
            const uint64_t* value, POLY_ARGUMENTS, const Modulus* moduli,
            const uint64_t* base_prod,
            const uint64_t* punctured_prod_array,
            const MultiplyUIntModOperand* inv_punctured_prod_mod_base_array,
            uint64_t* temp, uint64_t* result
        ) {
            GET_INDEX_COND_RETURN(poly_modulus_degree);
            uint64_t* temp_target = temp + gindex * coeff_modulus_size;
            FOR_N(rns_index, coeff_modulus_size) temp_target[rns_index] = 0;
            FOR_N(rns_index, coeff_modulus_size) {
                uint64_t temp_prod = kernel_util::dMultiplyUintMod(
                    value[rns_index * poly_modulus_degree + gindex],
                    inv_punctured_prod_mod_base_array[rns_index], moduli[rns_index]);
                kernel_util::dMultiplyUint(
                    punctured_prod_array + rns_index * coeff_modulus_size, 
                    coeff_modulus_size, temp_prod, coeff_modulus_size, temp_target);
                kernel_util::dAddUintUintMod(temp_target, 
                    result + gindex * coeff_modulus_size, 
                    base_prod, coeff_modulus_size, result + gindex * coeff_modulus_size);
            }
        }

        void RNSBaseCuda::decomposeArray(DevicePointer<uint64_t> values, size_t coeff_count) const {
            if (size_ <= 1) return;
            // FIXME: temporary array -> rnsbase. could use dynamic array
            DeviceArray<uint64_t> copy(size_ * coeff_count);
            KernelProvider::copyOnDevice(copy.get(), values.get(), size_ * coeff_count);
            KERNEL_CALL(gDecomposeArray, coeff_count)(
                copy.get(), size_, coeff_count, base_.get(), values.get()
            );
        }

        void RNSBaseCuda::composeArray(DevicePointer<uint64_t> values, size_t coeff_count) const {
            if (size_ <= 1) return;
            // FIXME: temporary array -> rnsbase. could use dynamic array
            DeviceArray<uint64_t> copy(size_ * coeff_count);
            DeviceArray<uint64_t> temp(size_ * coeff_count);
            KernelProvider::copyOnDevice(copy.get(), values.get(), size_ * coeff_count);
            KernelProvider::memsetZero<uint64_t>(values.get(), size_ * coeff_count);
            KERNEL_CALL(gComposeArray, coeff_count)(
                copy.get(), size_, coeff_count,
                base_.get(), base_prod_.get(), punctured_prod_array_.get(),
                inv_punctured_prod_mod_base_array_.get(), temp.get(), values.get()
            );
        }

        __global__ void gFastConvertArrayStepA(
            const uint64_t* in,
            size_t ibase_size,
            size_t count,
            const Modulus* moduli,
            const MultiplyUIntModOperand* inv_punctured_prod_mod_base_array,
            uint64_t* out
        ) {
            GET_INDEX_COND_RETURN(count);
            FOR_N(i, ibase_size) {
                MultiplyUIntModOperand r = inv_punctured_prod_mod_base_array[i];
                if (r.operand == 1)
                    out[gindex * ibase_size + i] = kernel_util::dBarrettReduce64(in[i * count + gindex], moduli[i]);
                else
                    out[gindex * ibase_size + i] = kernel_util::dMultiplyUintMod(in[i * count + gindex], r, moduli[i]);
            }
        }

        __global__ void gFastConvertArrayStepB(
            const uint64_t* in,
            size_t ibase_size,
            size_t obase_size,
            size_t count,
            const Modulus* moduli,
            const uint64_t* base_change_matrix_,
            uint64_t* out
        ) {
            GET_INDEX_COND_RETURN(count);
            FOR_N(i, obase_size) {
                out[i * count + gindex] = kernel_util::dDotProductMod(in + gindex * ibase_size, base_change_matrix_ + i * ibase_size, ibase_size, moduli[i]);
            }
        }

        void BaseConverterCuda::fastConvertArray(ConstDevicePointer<uint64_t> in, DevicePointer<uint64_t> out, size_t count) const {
            
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();

            // FIXME: temporary array -> baseconverter.
            DeviceArray<uint64_t> temp(count * ibase_size);

            KERNEL_CALL(gFastConvertArrayStepA, count)(
                in.get(), ibase_size, count, ibase_.base().get(), 
                ibase_.invPuncturedProdModBaseArray().get(), temp.get()
            );
            gFastConvertArrayStepB<<<block_count, 256>>>(
                temp.get(), ibase_size, obase_size, count,
                obase_.base().get(), base_change_matrix_.get(), out.get()
            );

        }

        

        __global__ void gExactConvertArray(
            const uint64_t* in,
            size_t ibase_size,
            size_t count,
            const Modulus* ibase,
            const MultiplyUIntModOperand* inv_punctured_prod_mod_base_array,
            const uint64_t* ibase_prod,
            const Modulus* obase,
            const uint64_t* base_change_matrix,
            uint64_t* temp,
            uint64_t* out
        ) {
            GET_INDEX_COND_RETURN(count);
            double aggregated = 0;
            FOR_N(i, ibase_size) {
                MultiplyUIntModOperand r = inv_punctured_prod_mod_base_array[i];
                double divisor = static_cast<double>(DeviceHelper::getModulusValue(ibase[i]));
                uint64_t temp_single;
                if (r.operand == 1) {
                    temp_single = kernel_util::dBarrettReduce64(in[i * count + gindex], ibase[i]);
                } else {
                    temp_single = kernel_util::dMultiplyUintMod(in[i * count + gindex], r, ibase[i]);
                }
                temp[gindex * ibase_size + i] = temp_single;
                aggregated += static_cast<double>(temp_single) / divisor;
            }
            aggregated += 0.5;
            uint64_t rounded = static_cast<uint64_t>(aggregated);
            const Modulus& p = obase[0];
            uint64_t q_mod_p = kernel_util::dModuloUint(ibase_prod, ibase_size, p);
            uint64_t sum_mod_obase = kernel_util::dDotProductMod(temp + gindex * ibase_size, base_change_matrix, ibase_size, p);
            auto v_q_mod_p = kernel_util::dMultiplyUintMod(rounded, q_mod_p, p);
            out[gindex] = kernel_util::dSubUintMod(sum_mod_obase, v_q_mod_p, p);
        }


        void BaseConverterCuda::exactConvertArray(ConstDevicePointer<uint64_t> in, DevicePointer<uint64_t> out, size_t count) const {
            size_t ibase_size = ibase_.size();
            size_t obase_size = obase_.size();
            if (obase_size != 1)
                throw std::invalid_argument("out base in exact_convert_array must be one.");

            // FIXME: temporary array -> baseconverter.
            DeviceArray<uint64_t> temp(count * ibase_size);
            DeviceArray<uint64_t> aggregated_rounded_v(count);
            KERNEL_CALL(gExactConvertArray, count)(
                in.get(), ibase_size, count,
                ibase_.base().get(),
                ibase_.invPuncturedProdModBaseArray().get(),
                ibase_.baseProd().get(),
                obase_.base().get(),
                base_change_matrix_.get(),
                temp.get(),
                out.get()
            );
            auto p = temp.toHost();
            // for (size_t i = 0; i < p.size(); i++)
            //     std::cout << "temp[" << i << "]=" << p[i] << std::endl;
        }

    }

}