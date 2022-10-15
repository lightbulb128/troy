// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "rlwe_cuda.cuh"
#include "../kernelutils.cuh"

using namespace std;


namespace troy
{
    namespace util
    {
        

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

        void encryptZeroAsymmetric(
            const PublicKeyCuda &public_key, const SEALContextCuda &context, ParmsID parms_id, bool is_ntt_form,
            CiphertextCuda &destination)
        {
            // We use a fresh memory pool with `clear_on_destruction' enabled

            auto &context_data = *context.getContextData(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            auto &plain_modulus = parms.plainModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();
            size_t coeff_power = getPowerOfTwo(coeff_count);
            auto ntt_tables = context_data.smallNTTTables();
            size_t encrypted_size = public_key.data().size();
            SchemeType type = parms.scheme();

            // Make destination have right size and parms_id
            // Ciphertext (c_0,c_1, ...)
            destination.resize(context, parms_id, encrypted_size);
            destination.isNttForm() = is_ntt_form;
            destination.scale() = 1.0;
            destination.correctionFactor() = 1;

            // c[j] = public_key[j] * u + e[j] in BFV/CKKS = public_key[j] * u + p * e[j] in BGV
            // where e[j] <-- chi, u <-- R_3

            // Create a PRNG; u and the noise/error share the same PRNG
            auto prng = parms.randomGenerator()->create();

            // Generate u <-- R_3
            auto u_cpu(allocatePoly(coeff_count, coeff_modulus_size));
            samplePolyTernary(prng, parms.host(), u_cpu.get());
            DeviceArray u(u_cpu);

            // c[j] = u * public_key[j]
            kernel_util::kNttNegacyclicHarvey(u.get(), 1, coeff_modulus_size, coeff_power, ntt_tables);
            for (size_t j = 0; j < encrypted_size; j++)
            {
                kernel_util::kDyadicProductCoeffmod(u, public_key.data().data(j), 1, coeff_modulus_size, coeff_count, coeff_modulus, destination.data(j));
                if (!is_ntt_form) {
                    kernel_util::kInverseNttNegacyclicHarvey(destination.data(j), 1, coeff_modulus_size, coeff_power, ntt_tables);
                }
            }

            // Generate e_j <-- chi
            // c[j] = public_key[j] * u + e[j] in BFV/CKKS, = public_key[j] * u + p * e[j] in BGV,
            for (size_t j = 0; j < encrypted_size; j++)
            {
                samplePolyCbd(prng, parms.host(), u_cpu.get());
                u = DeviceArray(u_cpu);
                auto gaussian_iter = u.asPointer();

                // In BGV, p * e is used
                if (type == SchemeType::bgv)
                {
                    if (is_ntt_form)
                        kernel_util::kNttNegacyclicHarveyLazy(gaussian_iter, 1, coeff_modulus_size, coeff_power, ntt_tables);
                    kernel_util::kMultiplyPolyScalarCoeffmod(gaussian_iter, 1, coeff_modulus_size, coeff_count, plain_modulus.value(), coeff_modulus, gaussian_iter);
                }
                else
                {
                    if (is_ntt_form)
                        kernel_util::kNttNegacyclicHarvey(gaussian_iter, 1, coeff_modulus_size, coeff_power, ntt_tables);
                }
                kernel_util::kAddPolyCoeffmod(gaussian_iter, destination.data(j), 1, coeff_modulus_size, coeff_count, coeff_modulus, destination.data(j));
            }
        }

        // The second last argument "save_seed" is deleted. set it to false.
        void encryptZeroSymmetric(
            const SecretKeyCuda &secret_key, const SEALContextCuda &context, ParmsID parms_id, bool is_ntt_form,
            CiphertextCuda &destination)
        {
            // We use a fresh memory pool with `clear_on_destruction' enabled.

            auto &context_data = *context.getContextData(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeffModulus();
            auto &plain_modulus = parms.plainModulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.polyModulusDegree();
            size_t coeff_power = getPowerOfTwo(coeff_count);
            auto ntt_tables = context_data.smallNTTTables();
            size_t encrypted_size = 2;
            SchemeType type = parms.scheme();

            destination.resize(context, parms_id, encrypted_size);
            destination.isNttForm() = is_ntt_form;
            destination.scale() = 1.0;
            destination.correctionFactor() = 1;

            auto bootstrap_prng = parms.randomGenerator()->create();

            PRNGSeed public_prng_seed;
            bootstrap_prng->generate(prng_seed_byte_count, reinterpret_cast<byte *>(public_prng_seed.data()));

            auto ciphertext_prng = UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed);

            // Generate ciphertext: (c[0], c[1]) = ([-(as+ e)]_q, a) in BFV/CKKS
            // Generate ciphertext: (c[0], c[1]) = ([-(as+pe)]_q, a) in BGV
            auto c0 = destination.data();
            auto c1 = destination.data(1);

            // Sample a uniformly at random
            auto u_cpu = allocatePoly(coeff_count, coeff_modulus_size);
            samplePolyUniform(ciphertext_prng, parms.host(), u_cpu.get());
            KernelProvider::copy(c1.get(), u_cpu.get(), coeff_count * coeff_modulus_size);

            // Sample e <-- chi
            auto noise_cpu(allocatePoly(coeff_count, coeff_modulus_size));
            samplePolyCbd(bootstrap_prng, parms.host(), noise_cpu.get());
            DeviceArray noise(noise_cpu);

            // Calculate -(as+ e) (mod q) and store in c[0] in BFV/CKKS
            // Calculate -(as+pe) (mod q) and store in c[0] in BGV

            kernel_util::kDyadicProductCoeffmod(secret_key.data().data(), c1, 1, coeff_modulus_size, coeff_count, coeff_modulus, c0);
            if (is_ntt_form) {
                kernel_util::kNttNegacyclicHarvey(noise.get(), 1, coeff_modulus_size, coeff_power, ntt_tables);
            } else {
                kernel_util::kInverseNttNegacyclicHarvey(c0, 1, coeff_modulus_size, coeff_power, ntt_tables);
            }
            if (type == SchemeType::bgv) {
                kernel_util::kMultiplyPolyScalarCoeffmod(noise, 1, coeff_modulus_size, coeff_count, plain_modulus.value(), coeff_modulus, noise);
            }
            kernel_util::kAddPolyCoeffmod(noise, c0, 1, coeff_modulus_size, coeff_count, coeff_modulus, c0);
            kernel_util::kNegatePolyCoeffmod(c0, 1, coeff_modulus_size, coeff_count, coeff_modulus, c0);
            if (!is_ntt_form) {
                kernel_util::kInverseNttNegacyclicHarvey(c1, 1, coeff_modulus_size, coeff_power, ntt_tables);
            }

        }
    } // namespace util
} // namespace seal
