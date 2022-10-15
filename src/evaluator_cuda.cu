#include "evaluator_cuda.cuh"

using std::invalid_argument;
using std::logic_error;

#define KERNEL_CALL(funcname, n) size_t block_count = kernel_util::ceilDiv_(n, 256); funcname<<<block_count, 256>>>
#define POLY_ARRAY_ARGUMENTS size_t poly_size, size_t coeff_modulus_size, size_t poly_modulus_degree
#define POLY_ARRAY_ARGCALL poly_size, coeff_modulus_size, poly_modulus_degree
#define GET_INDEX size_t gindex = blockDim.x * blockIdx.x + threadIdx.x
#define GET_INDEX_COND_RETURN(n) size_t gindex = blockDim.x * blockIdx.x + threadIdx.x; if (gindex >= (n)) return
#define FOR_N(name, count) for (size_t name = 0; name < count; name++)

namespace troy {

    using namespace util;

    namespace {

        inline bool areClose(double value1, double value2) {
            double scale_factor = std::max({std::fabs(value1), std::fabs(value2), 1.0});
            return std::fabs(value1 - value2) < std::numeric_limits<double>::epsilon() * scale_factor;
        }

        inline bool isScaleWithinBounds(
            double scale, const SEALContextCuda::ContextDataCuda &context_data) noexcept
        {
            int scale_bit_count_bound = 0;
            switch (context_data.parms().scheme())
            {
            case SchemeType::bfv:
            case SchemeType::bgv:
                scale_bit_count_bound = context_data.parms().plainModulus().bitCount();
                break;
            case SchemeType::ckks:
                scale_bit_count_bound = context_data.totalCoeffModulusBitCount();
                break;
            default:
                // Unsupported scheme; check will fail
                scale_bit_count_bound = -1;
            };

            return !(scale <= 0 || (static_cast<int>(log2(scale)) >= scale_bit_count_bound));
        }
        
        inline auto balanceCorrectionFactors(
            uint64_t factor1, uint64_t factor2, const Modulus &plain_modulus) -> std::tuple<uint64_t, uint64_t, uint64_t>
        {
            uint64_t t = plain_modulus.value();
            uint64_t half_t = t / 2;

            auto sum_abs = [&](uint64_t x, uint64_t y) {
                int64_t x_bal = static_cast<int64_t>(x > half_t ? x - t : x);
                int64_t y_bal = static_cast<int64_t>(y > half_t ? y - t : y);
                return abs(x_bal) + abs(y_bal);
            };

            // ratio = f2 / f1 mod p
            uint64_t ratio = 1;
            if (!util::tryInvertUintMod(factor1, plain_modulus, ratio))
            {
                throw std::logic_error("invalid correction factor1");
            }
            ratio = util::multiplyUintMod(ratio, factor2, plain_modulus);
            uint64_t e1 = ratio;
            uint64_t e2 = 1;
            int64_t sum = sum_abs(e1, e2);

            // Extended Euclidean
            int64_t prev_a = static_cast<int64_t>(plain_modulus.value());
            int64_t prev_b = static_cast<int64_t>(0);
            int64_t a = static_cast<int64_t>(ratio);
            int64_t b = 1;

            while (a != 0)
            {
                int64_t q = prev_a / a;
                int64_t temp = prev_a % a;
                prev_a = a;
                a = temp;

                temp = util::sub_safe(prev_b, util::mul_safe(b, q));
                prev_b = b;
                b = temp;

                uint64_t a_mod = util::barrettReduce64(static_cast<uint64_t>(abs(a)), plain_modulus);
                if (a < 0)
                {
                    a_mod = util::negateUintMod(a_mod, plain_modulus);
                }
                uint64_t b_mod = util::barrettReduce64(static_cast<uint64_t>(abs(b)), plain_modulus);
                if (b < 0)
                {
                    b_mod = util::negateUintMod(b_mod, plain_modulus);
                }
                if (a_mod != 0 && util::gcd(a_mod, t) == 1) // which also implies gcd(b_mod, t) == 1
                {
                    int64_t new_sum = sum_abs(a_mod, b_mod);
                    if (new_sum < sum)
                    {
                        sum = new_sum;
                        e1 = a_mod;
                        e2 = b_mod;
                    }
                }
            }
            return std::make_tuple(util::multiplyUintMod(e1, factor1, plain_modulus), e1, e2);
        }

        [[maybe_unused]] void printDeviceArray(const DeviceArray<uint64_t>& r, bool dont_compress = false) {
            HostArray<uint64_t> start = r.toHost();
            size_t count = r.size();
            std::cout << "dev[";
            for (size_t i = 0; i < count; i++) {
                if (!dont_compress && i == 5 && count >= 10) 
                    {i = count - 5; std::cout << "...";}
                std::cout << std::hex << start[i];
                if (i!=count-1) std::cout << ", ";
            }
            std::cout << "]\n";
        }

        [[maybe_unused]] void printDeviceArray(const uint64_t* r, size_t count, bool dont_compress = false) {
            HostArray<uint64_t> start(count);
            KernelProvider::retrieve(start.get(), r, count);
            std::cout << "dev[";
            for (size_t i = 0; i < count; i++) {
                if (!dont_compress && i == 5 && count >= 10) 
                    {i = count - 5; std::cout << "...";}
                std::cout << std::hex << start[i];
                if (i!=count-1) std::cout << ", ";
            }
            std::cout << "]\n";
        }

    }

    void EvaluatorCuda::negateInplace(CiphertextCuda& encrypted) const {
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        size_t encrypted_size = encrypted.size();

        kernel_util::kNegatePolyCoeffmod(encrypted.data(), encrypted_size, coeff_modulus.size(), parms.polyModulusDegree(), coeff_modulus, encrypted.data());
    }

    void EvaluatorCuda::addInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const {

        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        auto &plain_modulus = parms.plainModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        if (encrypted1.correctionFactor() != encrypted2.correctionFactor())
        {
            // Balance correction factors and multiply by scalars before addition in BGV
            auto factors = balanceCorrectionFactors(
                encrypted1.correctionFactor(), encrypted2.correctionFactor(), plain_modulus);
            kernel_util::kMultiplyPolyScalarCoeffmod(
                encrypted1.data(), encrypted1.size(), coeff_modulus_size, coeff_count, std::get<1>(factors),
                coeff_modulus.asPointer(), encrypted1.data());

            CiphertextCuda encrypted2_copy = encrypted2;
            kernel_util::kMultiplyPolyScalarCoeffmod(
                encrypted2.data(), encrypted2.size(), coeff_modulus_size, coeff_count, std::get<2>(factors),
                coeff_modulus.asPointer(), encrypted2_copy.data());

            // Set new correction factor
            encrypted1.correctionFactor() = std::get<0>(factors);
            encrypted2_copy.correctionFactor() = std::get<0>(factors);

            addInplace(encrypted1, encrypted2_copy);
        }
        else
        {
            // Prepare destination
            encrypted1.resize(context_, context_data.parmsID(), max_count);
            // Add ciphertexts
            kernel_util::kAddPolyCoeffmod(encrypted1.data(), encrypted2.data(), min_count, coeff_modulus_size, coeff_count, coeff_modulus.asPointer(), encrypted1.data());

            // Copy the remainding polys of the array with larger count into encrypted1
            if (encrypted1_size < encrypted2_size)
            {
                kernel_util::kSetPolyArray(
                    encrypted2.data(min_count), encrypted2_size - encrypted1_size, coeff_count, coeff_modulus_size,
                    encrypted1.data(encrypted1_size));
            }
        }

    }

    
    void EvaluatorCuda::subInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const {
        
        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeffModulus();
        auto &plain_modulus = parms.plainModulus();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        if (encrypted1.correctionFactor() != encrypted2.correctionFactor())
        {
            // Balance correction factors and multiply by scalars before addition in BGV
            auto factors = balanceCorrectionFactors(
                encrypted1.correctionFactor(), encrypted2.correctionFactor(), plain_modulus);
            kernel_util::kMultiplyPolyScalarCoeffmod(
                encrypted1.data(), encrypted1.size(), coeff_modulus_size, coeff_count, std::get<1>(factors),
                coeff_modulus.asPointer(), encrypted1.data());

            CiphertextCuda encrypted2_copy = encrypted2;
            kernel_util::kMultiplyPolyScalarCoeffmod(
                encrypted2.data(), encrypted2.size(), coeff_modulus_size, coeff_count, std::get<2>(factors),
                coeff_modulus.asPointer(), encrypted2_copy.data());

            // Set new correction factor
            encrypted1.correctionFactor() = std::get<0>(factors);
            encrypted2_copy.correctionFactor() = std::get<0>(factors);

            subInplace(encrypted1, encrypted2_copy);
        }
        else
        {
            // Prepare destination
            encrypted1.resize(context_, context_data.parmsID(), max_count);
            // Add ciphertexts
            kernel_util::kSubPolyCoeffmod(encrypted1.data(), encrypted2.data(), min_count, coeff_modulus_size, coeff_count, coeff_modulus.asPointer(), encrypted1.data());

            // Copy the remainding polys of the array with larger count into encrypted1
            if (encrypted1_size < encrypted2_size)
            {
                kernel_util::kNegatePolyCoeffmod(
                    encrypted2.data(min_count), encrypted2_size - encrypted1_size, coeff_count, coeff_modulus_size,
                    coeff_modulus, encrypted1.data(encrypted1_size));
            }
        }
    }

    void EvaluatorCuda::multiplyInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const {
        auto context_data_ptr = context_.firstContextData();
        switch (context_data_ptr->parms().scheme()) {
        case SchemeType::bfv:
            bfvMultiply(encrypted1, encrypted2);
            break;

        case SchemeType::ckks:
            ckksMultiply(encrypted1, encrypted2);
            break;

        case SchemeType::bgv:
            bgvMultiply(encrypted1, encrypted2);
            break;

        default:
            throw std::invalid_argument("unsupported scheme");
        }
    }

    void EvaluatorCuda::bfvMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const {
    
        if (encrypted1.isNttForm() || encrypted2.isNttForm())
            throw std::invalid_argument("encrypted1 or encrypted2 cannot be in NTT form");
    
        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t base_q_size = parms.coeffModulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        uint64_t plain_modulus = parms.plainModulus().value();

        auto rns_tool = context_data.rnsTool();
        size_t base_Bsk_size = rns_tool->baseBsk()->size();
        size_t base_Bsk_m_tilde_size = rns_tool->baseBskmTilde()->size();

        size_t dest_size = encrypted1_size + encrypted2_size - 1;

        auto base_q = parms.coeffModulus().get();
        auto base_Bsk = rns_tool->baseBsk()->base();
        
        auto base_q_ntt_tables = context_data.smallNTTTables();
        auto base_Bsk_ntt_tables = rns_tool->baseBskNttTables();

        auto coeff_power = util::getPowerOfTwo(coeff_count);
        
        encrypted1.resize(context_, context_data.parmsID(), dest_size);
        
        auto encrypted1_q = kernel_util::kAllocate(encrypted1_size, coeff_count, base_q_size);
        auto encrypted1_Bsk = kernel_util::kAllocate(encrypted1_size, coeff_count, base_Bsk_size);
        
        auto encrypted2_q = kernel_util::kAllocate(encrypted2_size, coeff_count, base_q_size);
        auto encrypted2_Bsk = kernel_util::kAllocate(encrypted2_size, coeff_count, base_Bsk_size);

        auto temp = kernel_util::kAllocate(coeff_count, base_Bsk_m_tilde_size);
        for (size_t i = 0; i < encrypted1_size; i++) {
            kernel_util::kSetPolyArray(encrypted1.data(i), 1, base_q_size, coeff_count, encrypted1_q.get() + i * coeff_count * base_q_size);
            kernel_util::kNttNegacyclicHarveyLazy(encrypted1_q.get() + i * coeff_count * base_q_size, 1, base_q_size, coeff_power, base_q_ntt_tables);
            rns_tool->fastbconvmTilde(encrypted1.data(i), temp.asPointer());
            rns_tool->smMrq(temp.asPointer(), encrypted1_Bsk.get() + i * coeff_count * base_Bsk_size);
            kernel_util::kNttNegacyclicHarveyLazy(encrypted1_Bsk.get() + i * coeff_count * base_Bsk_size, 1, base_Bsk_size, coeff_power, base_Bsk_ntt_tables);
        }
        for (size_t i = 0; i < encrypted2_size; i++) {
            kernel_util::kSetPolyArray(encrypted2.data(i), 1, base_q_size, coeff_count, encrypted2_q.get() + i * coeff_count * base_q_size);
            kernel_util::kNttNegacyclicHarveyLazy(encrypted2_q.get() + i * coeff_count * base_q_size, 1, base_q_size, coeff_power, base_q_ntt_tables);
            rns_tool->fastbconvmTilde(encrypted2.data(i), temp.asPointer());
            rns_tool->smMrq(temp.asPointer(), encrypted2_Bsk.get() + i * coeff_count * base_Bsk_size);
            kernel_util::kNttNegacyclicHarveyLazy(encrypted2_Bsk.get() + i * coeff_count * base_Bsk_size, 1, base_Bsk_size, coeff_power, base_Bsk_ntt_tables);
        }

        auto temp_dest_q = kernel_util::kAllocateZero(dest_size, coeff_count, base_q_size);
        auto temp_dest_Bsk = kernel_util::kAllocateZero(dest_size, coeff_count, base_Bsk_size);

        for (size_t i = 0; i < dest_size; i++) {
            size_t curr_encrypted1_last = std::min<size_t>(i, encrypted1_size - 1);
            size_t curr_encrypted2_first = std::min<size_t>(i, encrypted2_size - 1);
            size_t curr_encrypted1_first = i - curr_encrypted2_first;
            size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            {
                size_t d = coeff_count * base_q_size;
                auto shifted_in1_iter = encrypted1_q + curr_encrypted1_first * d;
                auto shifted_reversed_in2_iter = encrypted2_q + curr_encrypted2_first * d;
                auto shifted_out_iter = temp_dest_q + i * d;
                kernel_util::kDyadicConvolutionCoeffmod(shifted_in1_iter, shifted_reversed_in2_iter, steps, base_q_size, coeff_count,
                    base_q, shifted_out_iter);
            }
            {
                size_t d = coeff_count * base_Bsk_size;
                auto shifted_in1_iter = encrypted1_Bsk + curr_encrypted1_first * d;
                auto shifted_reversed_in2_iter = encrypted2_Bsk + curr_encrypted2_first * d;
                auto shifted_out_iter = temp_dest_Bsk + i * d;
                kernel_util::kDyadicConvolutionCoeffmod(shifted_in1_iter, shifted_reversed_in2_iter, steps, base_Bsk_size, coeff_count,
                    base_Bsk, shifted_out_iter);
            }
        }

        kernel_util::kInverseNttNegacyclicHarveyLazy(temp_dest_q.asPointer(), dest_size, base_q_size, coeff_power, base_q_ntt_tables);
        kernel_util::kInverseNttNegacyclicHarveyLazy(temp_dest_Bsk.asPointer(), dest_size, base_Bsk_size, coeff_power, base_Bsk_ntt_tables);

        auto temp_q_Bsk = kernel_util::kAllocate(coeff_count, base_q_size + base_Bsk_size);
        auto temp_Bsk = kernel_util::kAllocate(coeff_count, base_Bsk_size);
        for (size_t i = 0; i < dest_size; i++) {
            kernel_util::kMultiplyPolyScalarCoeffmod(temp_dest_q + i * coeff_count * base_q_size, 
                1, base_q_size, coeff_count, 
                plain_modulus, base_q, temp_q_Bsk);
            kernel_util::kMultiplyPolyScalarCoeffmod(temp_dest_Bsk + i * coeff_count * base_Bsk_size, 
                1, base_Bsk_size, coeff_count, 
                plain_modulus, base_Bsk, temp_q_Bsk + base_q_size * coeff_count);
            rns_tool->fastFloor(temp_q_Bsk.asPointer(), temp_Bsk.asPointer());
            rns_tool->fastbconvSk(temp_Bsk.asPointer(), encrypted1.data(i));
        }

    }
    
    void EvaluatorCuda::ckksMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const {
        
        if (!(encrypted1.isNttForm() && encrypted2.isNttForm()))
            throw std::invalid_argument("encrypted1 or encrypted2 must be in NTT form");

        
        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();

        auto& coeff_modulus = parms.coeffModulus();

        size_t dest_size = encrypted1_size + encrypted2_size - 1;

        encrypted1.resize(context_, context_data.parmsID(), dest_size);

        // FIXME: temporary array -> evaluator
        auto temp = kernel_util::kAllocateZero(dest_size, coeff_count, coeff_modulus_size);

        for (size_t i = 0; i < dest_size; i++) {
            size_t curr_encrypted1_last = std::min<size_t>(i, encrypted1_size - 1);
            size_t curr_encrypted2_first = std::min<size_t>(i, encrypted2_size - 1);
            size_t curr_encrypted1_first = i - curr_encrypted2_first;
            size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;
            auto shifted_encrypted1_iter = encrypted1.data(curr_encrypted1_first);
            auto shifted_reversed_encrypted2_iter = encrypted2.data(curr_encrypted2_first);

            kernel_util::kDyadicConvolutionCoeffmod(
                shifted_encrypted1_iter,
                shifted_reversed_encrypted2_iter,
                steps, coeff_modulus_size, coeff_count,
                coeff_modulus,
                temp + i * coeff_count * coeff_modulus_size
            );

        }

        kernel_util::kSetPolyArray(temp, dest_size, 
            coeff_modulus_size, coeff_count, encrypted1.data());

        encrypted1.scale() *= encrypted2.scale();
        if (!isScaleWithinBounds(encrypted1.scale(), context_data))
            throw std::invalid_argument("scale out of bounds");

    }


    void EvaluatorCuda::bgvMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const
    {
        if (encrypted1.isNttForm() || encrypted2.isNttForm())
        {
            throw std::invalid_argument("encryped1 or encrypted2 must be not in NTT form");
        }

        auto &context_data = *context_.getContextData(encrypted1.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        auto ntt_table = context_data.smallNTTTables();

        size_t dest_size = encrypted1_size + encrypted2_size - 1;

        // Set up iterator for the base
        auto coeff_modulus = parms.coeffModulus().get();

        // Prepare destination
        encrypted1.resize(context_, context_data.parmsID(), dest_size);

        size_t coeff_power = getPowerOfTwo(coeff_count);

        // Convert c0 and c1 to ntt
        // Set up iterators for input ciphertexts
        DevicePointer<uint64_t> encrypted1_iter = encrypted1.data();
        kernel_util::kNttNegacyclicHarvey(encrypted1.data(), encrypted1_size, coeff_modulus_size, coeff_power, ntt_table);
        DevicePointer<uint64_t> encrypted2_iter;
        CiphertextCuda encrypted2_cpy;
        if (&encrypted1 == &encrypted2)
        {
            encrypted2_iter = encrypted1.data();
        }
        else
        {
            encrypted2_cpy = encrypted2;
            kernel_util::kNttNegacyclicHarvey(encrypted2_cpy.data(), encrypted2_size, coeff_modulus_size, coeff_power, ntt_table);
            encrypted2_iter = encrypted2_cpy.data();
        }

        // Allocate temporary space for the result
        auto temp = kernel_util::kAllocateZero(dest_size, coeff_count, coeff_modulus_size);

        for (size_t i = 0; i < dest_size; i++) {
            size_t curr_encrypted1_last = std::min<size_t>(i, encrypted1_size - 1);
            size_t curr_encrypted2_first = std::min<size_t>(i, encrypted2_size - 1);
            size_t curr_encrypted1_first = i - curr_encrypted2_first;
            size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            size_t d = coeff_count * coeff_modulus_size;
            auto shifted_encrypted1_iter = encrypted1_iter + curr_encrypted1_first * d;
            auto shifted_reversed_encrypted2_iter = encrypted2_iter + curr_encrypted2_first * d;

            kernel_util::kDyadicConvolutionCoeffmod(
                shifted_encrypted1_iter, shifted_reversed_encrypted2_iter, steps,
                coeff_modulus_size, coeff_count, coeff_modulus, temp + i * d
            );
        }

        kernel_util::kSetPolyArray(temp.get(), dest_size, coeff_modulus_size, coeff_count, encrypted1.data());
        kernel_util::kInverseNttNegacyclicHarvey(encrypted1.data(), encrypted1.size(), coeff_modulus_size, coeff_power, ntt_table);
        encrypted1.correctionFactor() =
            multiplyUintMod(encrypted1.correctionFactor(), encrypted2.correctionFactor(), parms.plainModulus());
    }

    void EvaluatorCuda::squareInplace(CiphertextCuda& encrypted) const {
        auto context_data_ptr = context_.firstContextData();
        switch (context_data_ptr->parms().scheme())
        {
        case SchemeType::bfv:
            bfvSquare(encrypted);
            break;

        case SchemeType::ckks:
            ckksSquare(encrypted);
            break;

        case SchemeType::bgv:
            bgvSquare(encrypted);
            break;

        default:
            throw std::invalid_argument("unsupported scheme");
        }
    }

    void EvaluatorCuda::bfvSquare(CiphertextCuda &encrypted) const
    {
        if (encrypted.isNttForm())
        {
            throw std::invalid_argument("encrypted cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t base_q_size = parms.coeffModulus().size();
        size_t encrypted_size = encrypted.size();
        uint64_t plain_modulus = parms.plainModulus().value();

        auto rns_tool = context_data.rnsTool();
        size_t base_Bsk_size = rns_tool->baseBsk()->size();
        size_t base_Bsk_m_tilde_size = rns_tool->baseBskmTilde()->size();

        if (encrypted_size != 2)
        {
            bfvMultiply(encrypted, encrypted);
            return;
        }

        size_t dest_size = encrypted_size * 2 - 1;
        size_t coeff_power = util::getPowerOfTwo(coeff_count);

        auto base_q = parms.coeffModulus().get();
        auto base_Bsk = rns_tool->baseBsk()->base();

        auto base_q_ntt_tables = context_data.smallNTTTables();
        auto base_Bsk_ntt_tables = rns_tool->baseBskNttTables();

        encrypted.resize(context_, context_data.parmsID(), dest_size);

        auto encrypted_q = kernel_util::kAllocate(encrypted_size, coeff_count, base_q_size);
        auto encrypted_Bsk = kernel_util::kAllocate(encrypted_size, coeff_count, base_Bsk_size);
        
        // FIXME: temporary array
        auto temp = kernel_util::kAllocate(coeff_count, base_Bsk_m_tilde_size);
        for (size_t i = 0; i < encrypted_size; i++) {
            kernel_util::kSetPolyArray(encrypted.data(i), 1, base_q_size, coeff_count, encrypted_q.get() + i * coeff_count * base_q_size);
            kernel_util::kNttNegacyclicHarveyLazy(encrypted_q.get() + i * coeff_count * base_q_size, 1, base_q_size, coeff_power, base_q_ntt_tables);
            rns_tool->fastbconvmTilde(encrypted.data(i), temp.asPointer());
            rns_tool->smMrq(temp.asPointer(), encrypted_Bsk.get() + i * coeff_count * base_Bsk_size);
            kernel_util::kNttNegacyclicHarveyLazy(encrypted_Bsk.get() + i * coeff_count * base_Bsk_size, 1, base_Bsk_size, coeff_power, base_Bsk_ntt_tables);
        }

        // printf("encrypted_q = "); printDeviceArray(encrypted_q);
        // printf("encrypted_Bsk = "); printDeviceArray(encrypted_Bsk);

        auto temp_dest_q = kernel_util::kAllocateZero(dest_size, coeff_count, base_q_size);
        auto temp_dest_Bsk = kernel_util::kAllocateZero(dest_size, coeff_count, base_Bsk_size);

        kernel_util::kDyadicSquareCoeffmod(encrypted_q, base_q_size, coeff_count, base_q, temp_dest_q);
        kernel_util::kDyadicSquareCoeffmod(encrypted_Bsk, base_Bsk_size, coeff_count, base_Bsk, temp_dest_Bsk);

        kernel_util::kInverseNttNegacyclicHarveyLazy(temp_dest_q.asPointer(), dest_size, base_q_size, coeff_power, base_q_ntt_tables);
        kernel_util::kInverseNttNegacyclicHarveyLazy(temp_dest_Bsk.asPointer(), dest_size, base_Bsk_size, coeff_power, base_Bsk_ntt_tables);

        auto temp_q_Bsk = kernel_util::kAllocate(coeff_count, base_q_size + base_Bsk_size);
        auto temp_Bsk = kernel_util::kAllocate(coeff_count, base_Bsk_size);
        for (size_t i = 0; i < dest_size; i++) {
            kernel_util::kMultiplyPolyScalarCoeffmod(temp_dest_q + i * coeff_count * base_q_size, 
                1, base_q_size, coeff_count, 
                plain_modulus, base_q, temp_q_Bsk);
            kernel_util::kMultiplyPolyScalarCoeffmod(temp_dest_Bsk + i * coeff_count * base_Bsk_size, 
                1, base_Bsk_size, coeff_count, 
                plain_modulus, base_Bsk, temp_q_Bsk + base_q_size * coeff_count);
            rns_tool->fastFloor(temp_q_Bsk.asPointer(), temp_Bsk.asPointer());
            rns_tool->fastbconvSk(temp_Bsk.asPointer(), encrypted.data(i));
        }
    }

    void EvaluatorCuda::ckksSquare(CiphertextCuda &encrypted) const
    {
        if (!encrypted.isNttForm())
        {
            throw std::invalid_argument("encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t encrypted_size = encrypted.size();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            ckksMultiply(encrypted, encrypted);
            return;
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = 3;

        // Set up iterator for the base
        auto& coeff_modulus = parms.coeffModulus();

        // Prepare destination
        encrypted.resize(context_, context_data.parmsID(), dest_size);

        // Set up iterators for input ciphertext
        auto encrypted_iter = encrypted.data();

        // Compute c1^2
        kernel_util::kDyadicSquareCoeffmod(encrypted.data(), coeff_modulus_size, coeff_count, coeff_modulus);

        // Set the scale
        encrypted.scale() *= encrypted.scale();
        if (!isScaleWithinBounds(encrypted.scale(), context_data))
        {
            throw std::invalid_argument("scale out of bounds");
        }
    }


    void EvaluatorCuda::bgvSquare(CiphertextCuda &encrypted) const
    {
        if (encrypted.isNttForm())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.getContextData(encrypted.parmsID());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_modulus_size = parms.coeffModulus().size();
        size_t encrypted_size = encrypted.size();
        auto ntt_table = context_data.smallNTTTables();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            bgvMultiply(encrypted, encrypted);
            return;
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = encrypted_size * 2 - 1;
        size_t coeff_power = util::getPowerOfTwo(coeff_count);

        // Set up iterator for the base
        auto coeff_modulus = parms.coeffModulus().get();

        // Prepare destination
        encrypted.resize(context_, context_data.parmsID(), dest_size);

        // Convert c0 and c1 to ntt
        kernel_util::kNttNegacyclicHarvey(encrypted.data(), encrypted_size, coeff_modulus_size, coeff_power, ntt_table);

        // Set up iterators for input ciphertext
        auto encrypted_iter = encrypted.data();

        auto temp = kernel_util::kAllocateZero(dest_size, coeff_count, coeff_modulus_size);

        kernel_util::kDyadicSquareCoeffmod(encrypted_iter.get(), coeff_modulus_size, coeff_count, coeff_modulus, temp);

        // Set the final result
        kernel_util::kSetPolyArray(temp.get(), dest_size, coeff_count, coeff_modulus_size, encrypted.data());

        // Convert the final output to Non-NTT form
        kernel_util::kInverseNttNegacyclicHarvey(encrypted.data(), dest_size, coeff_modulus_size, coeff_power, ntt_table);

        // Set the correction factor
        encrypted.correctionFactor() =
            multiplyUintMod(encrypted.correctionFactor(), encrypted.correctionFactor(), parms.plainModulus());
    }

    
    void EvaluatorCuda::relinearizeInternal(CiphertextCuda &encrypted, const RelinKeysCuda &relin_keys, std::size_t destination_size) const {

        // Verify parameters.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (!context_data_ptr)
            throw invalid_argument("encrypted is not valid for encryption parameters");
        if (relin_keys.parmsID() != context_.keyParmsID())
            throw invalid_argument("relin_keys is not valid for encryption parameters");

        size_t encrypted_size = encrypted.size();

        // Verify parameters.
        if (destination_size < 2 || destination_size > encrypted_size)
            throw invalid_argument("destination_size must be at least 2 and less than or equal to current count");
        if (relin_keys.size() < sub_safe(encrypted_size, size_t(2)))
            throw invalid_argument("not enough relinearization keys");

        if (destination_size == encrypted_size)
            return;

        // Calculate number of relinearize_one_step calls needed
        size_t relins_needed = encrypted_size - destination_size;

        // Iterator pointing to the last component of encrypted
        auto encrypted_iter = encrypted.data(encrypted_size - 1);

        for (size_t i = 0; i < relins_needed; i++) {
            // std::cout << "encrypted_iter diff = " << std::dec << encrypted_iter - encrypted.data() << std::endl;
            this->switchKeyInplace(
                encrypted, encrypted_iter, static_cast<const KSwitchKeysCuda &>(relin_keys),
                RelinKeys::getIndex(encrypted_size - 1 - i));
            // std::cout << "relinearization " << i << ":";
            // printArray(encrypted.data(), encrypted.dynArray().size());
        }

        // Put the output of final relinearization into destination.
        // Prepare destination only at this point because we are resizing down
        // std::cout << "relin internal size = " << destination_size << std::endl;
        encrypted.resize(context_, context_data_ptr->parmsID(), destination_size);
        // std::cout << "relin internal size after = " << encrypted.dynArray().size() << std::endl;
    }




    void EvaluatorCuda::modSwitchScaleToNext(
        const CiphertextCuda &encrypted, CiphertextCuda &destination) const
    {
        // Assuming at this point encrypted is already validated.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (context_data_ptr->parms().scheme() == SchemeType::bfv && encrypted.isNttForm())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == SchemeType::ckks && !encrypted.isNttForm())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == SchemeType::bgv && encrypted.isNttForm())
        {
            throw invalid_argument("BGV encrypted cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &next_context_data = *context_data.nextContextData();
        auto &next_parms = next_context_data.parms();
        auto rns_tool = context_data.rnsTool();

        size_t encrypted_size = encrypted.size();
        size_t coeff_count = next_parms.polyModulusDegree();
        size_t next_coeff_modulus_size = next_parms.coeffModulus().size();
        
        // size_t d = context_data.parms().coeffModulus().size() * context_

        CiphertextCuda encrypted_copy;
        encrypted_copy = encrypted;

        switch (next_parms.scheme())
        {
        case SchemeType::bfv:
            for (size_t i = 0; i < encrypted_size; i++) 
                rns_tool->divideAndRoundqLastInplace(encrypted_copy.data(i));
            break;

        case SchemeType::ckks:
            for (size_t i = 0; i < encrypted_size; i++) 
                rns_tool->divideAndRoundqLastNttInplace(encrypted_copy.data(i), context_data.smallNTTTables());
            break;

        case SchemeType::bgv:
            for (size_t i = 0; i < encrypted_size; i++) 
                rns_tool->modTAndDivideqLastInplace(encrypted_copy.data(i));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }

        // Copy result to destination
        destination.resize(context_, next_context_data.parmsID(), encrypted_size);
        for (size_t i = 0; i < encrypted_size; i++) {
            kernel_util::kSetPolyArray(encrypted_copy.data(i), 1, next_coeff_modulus_size, coeff_count, destination.data(i));
        }

        // Set other attributes
        destination.isNttForm() = encrypted.isNttForm();
        if (next_parms.scheme() == SchemeType::ckks)
        {
            // Change the scale when using CKKS
            destination.scale() =
                encrypted.scale() / static_cast<double>(context_data.parms().coeffModulus().back().value());
        }
        else if (next_parms.scheme() == SchemeType::bgv)
        {
            // Change the correction factor when using BGV
            destination.correctionFactor() = multiplyUintMod(
                encrypted.correctionFactor(), rns_tool->invqLastModt(), next_parms.plainModulus());
        }
    }

    void EvaluatorCuda::modSwitchDropToNext(
        const CiphertextCuda &encrypted, CiphertextCuda &destination) const
    {
        // Assuming at this point encrypted is already validated.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (context_data_ptr->parms().scheme() == SchemeType::ckks && !encrypted.isNttForm())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->nextContextData();
        auto &next_parms = next_context_data.parms();

        if (!isScaleWithinBounds(encrypted.scale(), next_context_data))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        size_t next_coeff_modulus_size = next_parms.coeffModulus().size();
        size_t coeff_count = next_parms.polyModulusDegree();
        size_t encrypted_size = encrypted.size();

        // Size check
        if (!productFitsIn(encrypted_size, mul_safe(coeff_count, next_coeff_modulus_size)))
        {
            throw logic_error("invalid parameters");
        }

        if (&encrypted == &destination)
        {
            // Switching in-place so need temporary space
            auto temp = kernel_util::kAllocate(encrypted_size, coeff_count, next_coeff_modulus_size);

            // Copy data over to temp; only copy the RNS components relevant after modulus drop
            for (size_t i = 0; i < encrypted_size; i++) {
                kernel_util::kSetPolyArray(encrypted.data(i), 1, next_coeff_modulus_size, coeff_count,
                    temp + i * coeff_count * next_coeff_modulus_size);
            }

            // Resize destination before writing
            destination.resize(context_, next_context_data.parmsID(), encrypted_size);

            // Copy data to destination
            kernel_util::kSetPolyArray(temp, encrypted_size, coeff_count, next_coeff_modulus_size, destination.data());
            // TODO: avoid copying and temporary space allocation
        }
        else
        {
            // Resize destination before writing
            destination.resize(context_, next_context_data.parmsID(), encrypted_size);

            // Copy data over to destination; only copy the RNS components relevant after modulus drop
            for (size_t i = 0; i < encrypted_size; i++) {
                kernel_util::kSetPolyArray(encrypted.data(i), 1, next_coeff_modulus_size, coeff_count, 
                    destination.data(i));
            }
        }
        destination.isNttForm() = true;
        destination.scale() = encrypted.scale();
        destination.correctionFactor() = encrypted.correctionFactor();
    }

    void EvaluatorCuda::modSwitchDropToNext(PlaintextCuda &plain) const
    {
        // Assuming at this point plain is already validated.
        auto context_data_ptr = context_.getContextData(plain.parmsID());
        if (!plain.isNttForm())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (!context_data_ptr->nextContextData())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->nextContextData();
        auto &next_parms = context_data_ptr->nextContextData()->parms();

        if (!isScaleWithinBounds(plain.scale(), next_context_data))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        auto &next_coeff_modulus = next_parms.coeffModulus();
        size_t next_coeff_modulus_size = next_coeff_modulus.size();
        size_t coeff_count = next_parms.polyModulusDegree();

        // Compute destination size first for exception safety
        auto dest_size = mul_safe(next_coeff_modulus_size, coeff_count);

        plain.parmsID() = parmsIDZero;
        plain.resize(dest_size);
        plain.parmsID() = next_context_data.parmsID();
    }

    void EvaluatorCuda::modSwitchToNext(
        const CiphertextCuda &encrypted, CiphertextCuda &destination) const
    {

        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (context_.lastParmsID() == encrypted.parmsID())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }

        switch (context_.firstContextData()->parms().scheme())
        {
        case SchemeType::bfv:
            // Modulus switching with scaling
            modSwitchScaleToNext(encrypted, destination);
            break;

        case SchemeType::ckks:
            // Modulus switching without scaling
            modSwitchDropToNext(encrypted, destination);
            break;

        case SchemeType::bgv:
            modSwitchScaleToNext(encrypted, destination);
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void EvaluatorCuda::modSwitchToInplace(CiphertextCuda &encrypted, ParmsID parms_id) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        auto targetContextData_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!targetContextData_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chainIndex() < targetContextData_ptr->chainIndex())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (encrypted.parmsID() != parms_id)
        {
            modSwitchToNextInplace(encrypted);
        }
    }

    void EvaluatorCuda::modSwitchToInplace(PlaintextCuda &plain, ParmsID parms_id) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(plain.parmsID());
        auto targetContextData_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (!context_.getContextData(parms_id))
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!plain.isNttForm())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (context_data_ptr->chainIndex() < targetContextData_ptr->chainIndex())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (plain.parmsID() != parms_id)
        {
            modSwitchToNextInplace(plain);
        }
    }



    __global__ void gSwitchKeyInplaceUtilA(
        uint64_t* t_poly_lazy,
        size_t coeff_count,
        size_t key_component_count,
        const uint64_t* key_vector_j,
        size_t key_poly_coeff_size,
        const uint64_t* t_operand,
        size_t key_index,
        const Modulus* key_modulus
    ) {
        GET_INDEX_COND_RETURN(coeff_count);
        FOR_N(k, key_component_count) {
            uint64_t qword[2] {0, 0};
            const uint64_t* key_vector_j_k = key_vector_j + k * key_poly_coeff_size;
            kernel_util::dMultiplyUint64(t_operand[gindex], key_vector_j_k[key_index * coeff_count + gindex], qword);
            auto accumulator_l = t_poly_lazy + k * coeff_count * 2 + 2 * gindex;
            kernel_util::dAddUint128(qword, accumulator_l, qword);
            accumulator_l[0] = kernel_util::dBarrettReduce128(qword, key_modulus[key_index]);
            accumulator_l[1] = 0;
        }
    }

    __global__ void gSwitchKeyInplaceUtilB(
        uint64_t* t_poly_lazy,
        size_t coeff_count,
        size_t key_component_count,
        const uint64_t* key_vector_j,
        size_t key_poly_coeff_size,
        const uint64_t* t_operand,
        size_t key_index,
        const Modulus* key_modulus
    ) {
        GET_INDEX_COND_RETURN(coeff_count);
        FOR_N(k, key_component_count) {
            uint64_t qword[2] {0, 0};
            const uint64_t* key_vector_j_k = key_vector_j + k * key_poly_coeff_size;
            kernel_util::dMultiplyUint64(t_operand[gindex], key_vector_j_k[key_index * coeff_count + gindex], qword);
            auto accumulator_l = t_poly_lazy + k * coeff_count * 2 + 2 * gindex;
            kernel_util::dAddUint128(qword, accumulator_l, qword);
            accumulator_l[0] = qword[0];
            accumulator_l[1] = qword[1];
        }
    }

    __global__ void gSwitchKeyInplaceUtilC(
        const uint64_t* t_poly_lazy,
        size_t coeff_count,
        size_t key_component_count,
        size_t rns_modulus_size,
        uint64_t* t_poly_prod_iter
    ) {
        GET_INDEX_COND_RETURN(coeff_count);
        FOR_N(k, key_component_count) {
            const uint64_t* accumulator = t_poly_lazy + k * coeff_count * 2;
            t_poly_prod_iter[k * coeff_count * rns_modulus_size + gindex] = static_cast<uint64_t>(accumulator[gindex * 2]);
        }
    }

    __global__ void gSwitchKeyInplaceUtilD(
        const uint64_t* t_poly_lazy,
        size_t coeff_count,
        size_t key_component_count,
        size_t rns_modulus_size,
        uint64_t* t_poly_prod_iter,
        size_t key_index,
        const Modulus* key_modulus
    ) {
        GET_INDEX_COND_RETURN(coeff_count);
        FOR_N(k, key_component_count) {
            const uint64_t* accumulator = t_poly_lazy + k * coeff_count * 2;
            t_poly_prod_iter[k * coeff_count * rns_modulus_size + gindex] = 
                kernel_util::dBarrettReduce128(accumulator + gindex * 2, key_modulus[key_index]);
        }
    }

    __global__ void gSwitchKeyInplaceUtilE(
        const uint64_t* t_last,
        uint64_t* t_poly_prod_i,
        size_t coeff_count,
        const Modulus* plain_modulus,
        const Modulus* key_modulus,
        size_t decomp_modulus_size,
        size_t rns_modulus_size,
        uint64_t qk_inv_qp,
        uint64_t qk,
        const MultiplyUIntModOperand* modswitch_factors,
        uint64_t* encrypted_i
    ) {
        GET_INDEX_COND_RETURN(coeff_count);
        uint64_t k = kernel_util::dBarrettReduce64(t_last[gindex], *plain_modulus);
        k = kernel_util::dNegateUintMod(k, *plain_modulus);
        if (qk_inv_qp != 1) 
            k = kernel_util::dMultiplyScalarMod(k, qk_inv_qp, *plain_modulus);
        uint64_t delta = 0; uint64_t c_mod_qi = 0;
        FOR_N(j, decomp_modulus_size) {
            delta = kernel_util::dBarrettReduce64(k, key_modulus[j]);
            delta = kernel_util::dMultiplyScalarMod(delta, qk, key_modulus[j]);
            c_mod_qi = kernel_util::dBarrettReduce64(t_last[gindex], key_modulus[j]);
            const uint64_t Lqi = DeviceHelper::getModulusValue(key_modulus[j]) << 1;
            uint64_t& target = t_poly_prod_i[j * coeff_count + gindex];
            target = target + Lqi - (delta + c_mod_qi);
            target = kernel_util::dMultiplyUintMod(target, modswitch_factors[j], key_modulus[j]);
            encrypted_i[j * coeff_count + gindex] = kernel_util::dAddUintMod(target, encrypted_i[j * coeff_count + gindex], key_modulus[j]);
        }
    }

    __global__ void gSwitchKeyInplaceUtilF(
        uint64_t* t_last,
        size_t coeff_count,
        const Modulus* qk,
        const Modulus* key_modulus,
        uint64_t qk_half,
        size_t decomp_modulus_size,
        uint64_t* t_ntt // t_ntt should be at least coeff_count * decomp_modulus_size
    ) {
        GET_INDEX_COND_RETURN(coeff_count);
        t_last[gindex] = kernel_util::dBarrettReduce64(t_last[gindex] + qk_half, *qk);
        FOR_N(j, decomp_modulus_size) {
            const Modulus& qi = key_modulus[j];
            if (DeviceHelper::getModulusValue(*qk) > DeviceHelper::getModulusValue(qi)) {
                t_ntt[j * coeff_count + gindex] = kernel_util::dBarrettReduce64(t_last[gindex], qi);
            } else {
                t_ntt[j * coeff_count + gindex] = t_last[gindex];
            }
            uint64_t fix = DeviceHelper::getModulusValue(qi) - kernel_util::dBarrettReduce64(qk_half, key_modulus[j]);
            t_ntt[j * coeff_count + gindex] += fix;
        }
    }

    __global__ void gSwitchKeyInplaceUtilG(
        uint64_t* t_poly_prod_i,
        const uint64_t* t_ntt,
        size_t coeff_count,
        uint64_t* encrypted_i,
        bool is_ckks,
        size_t decomp_modulus_size,
        const Modulus* key_modulus,
        const MultiplyUIntModOperand* modswitch_factors
    ) {
        GET_INDEX_COND_RETURN(coeff_count);
        FOR_N(j, decomp_modulus_size) {
            uint64_t& dest = t_poly_prod_i[j*coeff_count + gindex];
            uint64_t qi = DeviceHelper::getModulusValue(key_modulus[j]);
            dest += ((is_ckks) ? (qi << 2) : (qi << 1)) - t_ntt[j * coeff_count + gindex];
            dest = kernel_util::dMultiplyUintMod(dest, modswitch_factors[j], key_modulus[j]);
            encrypted_i[j * coeff_count + gindex] = kernel_util::dAddUintMod(
                encrypted_i[j * coeff_count + gindex], dest, key_modulus[j]
            );
        }
    }

    
    void EvaluatorCuda::switchKeyInplace(
        CiphertextCuda &encrypted, ConstDevicePointer<uint64_t> target_iter, const KSwitchKeysCuda &kswitch_keys, size_t kswitch_keys_index) const
    {
        auto parms_id = encrypted.parmsID();
        auto &context_data = *context_.getContextData(parms_id);
        auto &parms = context_data.parms();
        auto &key_context_data = *context_.keyContextData();
        auto &key_parms = key_context_data.parms();
        auto scheme = parms.scheme();

        if (!context_.using_keyswitching())
            throw logic_error("keyswitching is not supported by the context");

        // Don't validate all of kswitch_keys but just check the parms_id.
        if (kswitch_keys.parmsID() != context_.keyParmsID())
            throw invalid_argument("parameter mismatch");

        if (kswitch_keys_index >= kswitch_keys.data().size())
            throw std::out_of_range("kswitch_keys_index");
        if (scheme == SchemeType::bfv && encrypted.isNttForm())
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        if (scheme == SchemeType::ckks && !encrypted.isNttForm())
            throw invalid_argument("CKKS encrypted must be in NTT form");
        if (scheme == SchemeType::bgv && encrypted.isNttForm())
            throw invalid_argument("BGV encrypted cannot be in NTT form");

        // Extract encryption parameters.
        size_t coeff_count = parms.polyModulusDegree();
        size_t coeff_power = getPowerOfTwo(coeff_count);
        size_t decomp_modulus_size = parms.coeffModulus().size();
        auto &key_modulus = key_parms.coeffModulus();
        auto key_modulus_cpu = key_modulus.toHost();
        size_t key_modulus_size = key_modulus.size();
        size_t rns_modulus_size = decomp_modulus_size + 1;
        auto key_ntt_tables = key_context_data.smallNTTTables();
        auto modswitch_factors = key_context_data.rnsTool()->invqLastModq();
        Modulus* plain_modulus_cuda_support = KernelProvider::malloc<Modulus>(1);
        KernelProvider::copy(plain_modulus_cuda_support, &(parms.plainModulus()), 1);
        DeviceObject<Modulus> plain_modulus_cuda(plain_modulus_cuda_support);

        // Prepare input
        auto &key_vector = kswitch_keys.data()[kswitch_keys_index];
        size_t key_component_count = key_vector[0].data().size();

        // Create a copy of target_iter
        // FIXME: temporary array
        auto t_target = kernel_util::kAllocate(coeff_count, decomp_modulus_size);
        kernel_util::kSetPolyArray(target_iter.get(), 1, decomp_modulus_size, coeff_count, t_target.get());

        // std::cout << "t_target: "; printDeviceArray(t_target);

        // In CKKS t_target is in NTT form; switch back to normal form
        if (scheme == SchemeType::ckks)
            kernel_util::kInverseNttNegacyclicHarvey(t_target.asPointer(), 1, decomp_modulus_size, coeff_power, key_ntt_tables);

        // Temporary result
        auto t_poly_prod = kernel_util::kAllocateZero(key_component_count, coeff_count, rns_modulus_size);

        for (size_t i = 0; i < rns_modulus_size; i++) {
            // std::cout << "i = " << i << std::endl;
            size_t key_index = (i == decomp_modulus_size ? key_modulus_size - 1 : i);
            size_t lazy_reduction_summand_bound = size_t(SEAL_MULTIPLY_ACCUMULATE_USER_MOD_MAX);
            size_t lazy_reduction_counter = lazy_reduction_summand_bound;
            auto t_poly_lazy = kernel_util::kAllocateZero(key_component_count, coeff_count, 2);
            // Semantic misuse of PolyIter; this is really pointing to the data for a single RNS factor
            // FIXME: temporary array
            auto t_ntt = kernel_util::kAllocate(coeff_count);
            for (size_t j = 0; j < decomp_modulus_size; j++) {
                ConstDevicePointer<uint64_t> t_operand;

                if ((scheme == SchemeType::ckks) && (i == j))
                    t_operand = target_iter + j * coeff_count;
                else
                {
                    if (key_modulus_cpu[j] <= key_modulus_cpu[key_index]) {
                        // printf("branch a - ");
                        kernel_util::kSetPolyArray(t_target.get() + j * coeff_count, 1, 1, coeff_count, t_ntt.get());
                    } else {
                        // printf("branch b - ");
                        kernel_util::kModuloPolyCoeffs(t_target.get() + j * coeff_count, 1, 1, coeff_count, key_modulus + key_index, t_ntt.get());
                    }
                    // printDeviceArray(t_ntt.get(), coeff_count);
                    kernel_util::kNttNegacyclicHarveyLazy(t_ntt.get(), 1, 1, coeff_power, key_ntt_tables + key_index);
                    t_operand = t_ntt.get();
                }
                
                // std::cout << "  j = " << j << std::endl;
                // std::cout << "  t_operand: "; printDeviceArray(t_operand.get(), coeff_count);

                size_t key_vector_poly_coeff_size = key_vector[j].data().polyCoeffSize();

                if (!lazy_reduction_counter) {
                    KERNEL_CALL(gSwitchKeyInplaceUtilA, coeff_count)(
                        t_poly_lazy.get(), coeff_count, key_component_count,
                        key_vector[j].data().data().get(), 
                        key_vector_poly_coeff_size,
                        t_operand.get(), key_index, key_modulus.get()
                    );
                } else {
                    KERNEL_CALL(gSwitchKeyInplaceUtilB, coeff_count)(
                        t_poly_lazy.get(), coeff_count, key_component_count,
                        key_vector[j].data().data().get(), 
                        key_vector_poly_coeff_size,
                        t_operand.get(), key_index, key_modulus.get()
                    );
                }

                if (!--lazy_reduction_counter)
                    lazy_reduction_counter = lazy_reduction_summand_bound;
            }

            // std::cout << "  t_poly_lazy: ";
            // printDeviceArray(t_poly_lazy);

            auto t_poly_prod_iter = t_poly_prod.get() + i * coeff_count;
            // PolyIter t_poly_prod_iter(t_poly_prod.get() + (I * coeff_count), coeff_count, rns_modulus_size);

            if (lazy_reduction_counter == lazy_reduction_summand_bound) {
                KERNEL_CALL(gSwitchKeyInplaceUtilC, coeff_count)(
                    t_poly_lazy.get(), coeff_count, key_component_count,
                    rns_modulus_size, t_poly_prod_iter
                );
            } else {
                KERNEL_CALL(gSwitchKeyInplaceUtilD, coeff_count)(
                    t_poly_lazy.get(), coeff_count, key_component_count,
                    rns_modulus_size, t_poly_prod_iter, key_index,
                    key_modulus.get()
                );
            }
        }
        // Accumulated products are now stored in t_poly_prod

        // std::cout << "t_poly_prod: ";
        // printDeviceArray(t_poly_prod, true);

        for (size_t i = 0; i < key_component_count; i++) {
            if (scheme == SchemeType::bgv)
            {
                const Modulus &plain_modulus = parms.plainModulus();
                // qk is the special prime
                uint64_t qk = key_modulus_cpu[key_modulus_size - 1].value();
                uint64_t qk_inv_qp = context_.keyContextData()->rnsTool()->invqLastModt();

                // Lazy reduction; this needs to be then reduced mod qi
                auto t_last = t_poly_prod + coeff_count * rns_modulus_size * i + decomp_modulus_size * coeff_count;
                kernel_util::kInverseNttNegacyclicHarvey(t_last, 1, 1, coeff_power, key_ntt_tables + (key_modulus_size - 1));
                kernel_util::kInverseNttNegacyclicHarvey(t_poly_prod + i * coeff_count * rns_modulus_size, 1, decomp_modulus_size, coeff_power, key_ntt_tables);

                KERNEL_CALL(gSwitchKeyInplaceUtilE, coeff_count)(
                    t_last.get(), t_poly_prod.get() + i * coeff_count * rns_modulus_size,
                    coeff_count, plain_modulus_cuda.get(), key_modulus.get(),
                    decomp_modulus_size, rns_modulus_size, qk_inv_qp, qk,
                    modswitch_factors, encrypted.data(i).get()
                );
            }
            else
            {
                // Lazy reduction; this needs to be then reduced mod qi
                auto t_last = t_poly_prod + coeff_count * rns_modulus_size * i + decomp_modulus_size * coeff_count;
                // std::cout << "t_last diff: " << coeff_count * rns_modulus_size * i + decomp_modulus_size * coeff_count << std::endl;
                auto t_ntt = kernel_util::kAllocateZero(decomp_modulus_size * coeff_count);
                // std::cout << "t_last: "; printArray(t_last.get(), coeff_count);
                kernel_util::kInverseNttNegacyclicHarvey(t_last, 1, 1, coeff_power, key_ntt_tables + (key_modulus_size - 1));

                KERNEL_CALL(gSwitchKeyInplaceUtilF, coeff_count)(
                    t_last.get(), coeff_count, key_modulus.get() + (key_modulus_size - 1),
                    key_modulus.get(), key_modulus_cpu[key_modulus_size - 1].value() >> 1,
                    decomp_modulus_size,
                    t_ntt.get()
                );
            
                if (scheme == SchemeType::ckks)
                    kernel_util::kNttNegacyclicHarveyLazy(t_ntt, 1, decomp_modulus_size, coeff_power, key_ntt_tables);
                else if (scheme == SchemeType::bfv)
                    kernel_util::kInverseNttNegacyclicHarveyLazy(
                        t_poly_prod + i * coeff_count * rns_modulus_size,
                        1, decomp_modulus_size, coeff_power,
                        key_ntt_tables
                    );

                // for (size_t j = 0; j < decomp_modulus_size; j++) {
                //     std::cout << "  t_ntt: " << j << " - ";
                //     printDeviceArray(t_ntt.get() + coeff_count * j, coeff_count);
                //     std::cout << "  t_ptr: " << j << " - "; printDeviceArray(t_poly_prod.get() + i * coeff_count * rns_modulus_size + j * coeff_count, coeff_count);
                // }


                gSwitchKeyInplaceUtilG<<<block_count, 256>>>(
                    t_poly_prod.get() + i * coeff_count * rns_modulus_size,
                    t_ntt.get(),
                    coeff_count, encrypted.data(i).get(), 
                    scheme==SchemeType::ckks, decomp_modulus_size, key_modulus.get(),
                    modswitch_factors
                );
            }
            // printf("enc %ld: ", i); printDeviceArray(encrypted.data(i).get(), key_component_count * coeff_count);
        }
    }

    

    void EvaluatorCuda::rescaleToNext(const CiphertextCuda &encrypted, CiphertextCuda &destination) const
    {
        if (context_.lastParmsID() == encrypted.parmsID())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }

        switch (context_.firstContextData()->parms().scheme())
        {
        case SchemeType::bfv:
            /* Fall through */
        case SchemeType::bgv:
            throw invalid_argument("unsupported operation for scheme type");

        case SchemeType::ckks:
            // Modulus switching with scaling
            modSwitchScaleToNext(encrypted, destination);
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }

    }


    void EvaluatorCuda::rescaleToInplace(CiphertextCuda &encrypted, ParmsID parms_id) const
    {

        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        auto targetContextData_ptr = context_.getContextData(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!targetContextData_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chainIndex() < targetContextData_ptr->chainIndex())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        switch (context_data_ptr->parms().scheme())
        {
        case SchemeType::bfv:
            /* Fall through */
        case SchemeType::bgv:
            throw invalid_argument("unsupported operation for scheme type");

        case SchemeType::ckks:
            while (encrypted.parmsID() != parms_id)
            {
                // Modulus switching with scaling
                modSwitchScaleToNext(encrypted, encrypted);
            }
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }


    void EvaluatorCuda::multiplyMany(
        const std::vector<CiphertextCuda> &encrypteds, const RelinKeysCuda &relin_keys, CiphertextCuda &destination) const
    {
        // Verify parameters.
        if (encrypteds.size() == 0)
        {
            throw invalid_argument("encrypteds vector must not be empty");
        }
        for (size_t i = 0; i < encrypteds.size(); i++)
        {
            if (&encrypteds[i] == &destination)
            {
                throw invalid_argument("encrypteds must be different from destination");
            }
        }

        // There is at least one ciphertext
        auto context_data_ptr = context_.getContextData(encrypteds[0].parmsID());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypteds is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();

        if (parms.scheme() != SchemeType::bfv && parms.scheme() != SchemeType::bgv)
        {
            throw logic_error("unsupported scheme");
        }

        // If there is only one ciphertext, return it.
        if (encrypteds.size() == 1)
        {
            destination = encrypteds[0];
            return;
        }

        // Do first level of multiplications
        std::vector<CiphertextCuda> product_vec;
        for (size_t i = 0; i < encrypteds.size() - 1; i += 2)
        {
            CiphertextCuda temp(context_, context_data.parmsID());
            if (encrypteds[i].data() == encrypteds[i + 1].data())
            {
                square(encrypteds[i], temp);
            }
            else
            {
                multiply(encrypteds[i], encrypteds[i + 1], temp);
            }
            relinearizeInplace(temp, relin_keys);
            product_vec.emplace_back(std::move(temp));
        }
        if (encrypteds.size() & 1)
        {
            product_vec.emplace_back(encrypteds.back());
        }

        // Repeatedly multiply and add to the back of the vector until the end is reached
        for (size_t i = 0; i < product_vec.size() - 1; i += 2)
        {
            CiphertextCuda temp(context_, context_data.parmsID());
            multiply(product_vec[i], product_vec[i + 1], temp);
            relinearizeInplace(temp, relin_keys);
            product_vec.emplace_back(std::move(temp));
        }

        destination = product_vec.back();
    }

    void EvaluatorCuda::exponentiateInplace(
        CiphertextCuda &encrypted, uint64_t exponent, const RelinKeysCuda &relin_keys) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.getContextData(encrypted.parmsID());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_.getContextData(relin_keys.parmsID()))
        {
            throw invalid_argument("relin_keys is not valid for encryption parameters");
        }
        if (exponent == 0)
        {
            throw invalid_argument("exponent cannot be 0");
        }

        // Fast case
        if (exponent == 1)
        {
            return;
        }

        // Create a vector of copies of encrypted
        std::vector<CiphertextCuda> exp_vector(static_cast<size_t>(exponent), encrypted);
        multiplyMany(exp_vector, relin_keys, encrypted);
    }

}