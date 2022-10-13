#include "evaluator_cuda.cuh"

namespace troy {

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
            throw std::invalid_argument("bfv multiply not implemented");
            bfvMultiply(encrypted1, encrypted2);
            break;

        case SchemeType::ckks:
            ckksMultiply(encrypted1, encrypted2);
            break;

        case SchemeType::bgv:
            throw std::invalid_argument("bgv multiply not implemented");
            // bgvMultiply(encrypted1, encrypted2);
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

        // auto rns_tool = context_data.rnsTool();
        // size_t base_Bsk_size = rns_tool->baseBsk()->size();
        // size_t base_Bsk_m_tilde_size = rns_tool->baseBskmTilde()->size();

        // size_t dest_size = encrypted1_size + encrypted2_size - 1;

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
            // size_t curr_encrypted2_last = secret_power_index - curr_encrypted1_last;

            // The total number of dyadic products is now easy to compute
            size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            auto shifted_encrypted1_iter = encrypted1.data(curr_encrypted1_first);

            // Create a shifted reverse iterator for the second input
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

    void EvaluatorCuda::squareInplace(CiphertextCuda& encrypted) const {
        auto context_data_ptr = context_.firstContextData();
        switch (context_data_ptr->parms().scheme())
        {
        case SchemeType::bfv:
            // bfvSquare(encrypted);
            throw std::invalid_argument("bfv square not implemented");
            break;

        case SchemeType::ckks:
            ckksSquare(encrypted);
            break;

        case SchemeType::bgv:
            // bgvSquare(encrypted);
            throw std::invalid_argument("bgv square not implemented");
            break;

        default:
            throw std::invalid_argument("unsupported scheme");
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

}