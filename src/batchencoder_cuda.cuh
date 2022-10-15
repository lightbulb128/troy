// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "batchencoder.h"
#include "plaintext_cuda.cuh"
#include "context_cuda.cuh"
#include <vector>

namespace troy
{
    /**
    Provides functionality for CRT batching. If the polynomial modulus degree is N, and
    the plaintext modulus is a prime number T such that T is congruent to 1 modulo 2N,
    then BatchEncoder allows the plaintext elements to be viewed as 2-by-(N/2)
    matrices of integers modulo T. Homomorphic operations performed on such encrypted
    matrices are applied coefficient (slot) wise, enabling powerful SIMD functionality
    for computations that are vectorizable. This functionality is often called "batching"
    in the homomorphic encryption literature.

    @par Mathematical Background
    Mathematically speaking, if the polynomial modulus is X^N+1, N is a power of two, and
    plain_modulus is a prime number T such that 2N divides T-1, then integers modulo T
    contain a primitive 2N-th root of unity and the polynomial X^N+1 splits into n distinct
    linear factors as X^N+1 = (X-a_1)*...*(X-a_N) mod T, where the constants a_1, ..., a_n
    are all the distinct primitive 2N-th roots of unity in integers modulo T. The Chinese
    Remainder Theorem (CRT) states that the plaintext space Z_T[X]/(X^N+1) in this case is
    isomorphic (as an algebra) to the N-fold direct product of fields Z_T. The isomorphism
    is easy to compute explicitly in both directions, which is what this class does.
    Furthermore, the Galois group of the extension is (Z/2NZ)* ~= Z/2Z x Z/(N/2) whose
    action on the primitive roots of unity is easy to describe. Since the batching slots
    correspond 1-to-1 to the primitive roots of unity, applying Galois automorphisms on the
    plaintext act by permuting the slots. By applying generators of the two cyclic
    subgroups of the Galois group, we can effectively view the plaintext as a 2-by-(N/2)
    matrix, and enable cyclic row rotations, and column rotations (row swaps).

    @par Valid Parameters
    Whether batching can be used depends on whether the plaintext modulus has been chosen
    appropriately. Thus, to construct a BatchEncoder the user must provide an instance
    of SEALContext such that its associated EncryptionParameterQualifiers object has the
    flags parameters_set and enable_batching set to true.

    @see EncryptionParameters for more information about encryption parameters.
    @see EncryptionParameterQualifiers for more information about parameter qualifiers.
    @see Evaluator for rotating rows and columns of encrypted matrices.
    */
    class BatchEncoderCuda
    {
    public:
        /**
        Creates a BatchEncoder. It is necessary that the encryption parameters
        given through the SEALContext object support batching.

        @param[in] context The SEALContext
        @throws std::invalid_argument if the encryption parameters are not valid for batching
        @throws std::invalid_argument if scheme is not scheme_type::bfv
        */
        BatchEncoderCuda(const SEALContextCuda &context): host(context.host()) {}

        /**
        Creates a plaintext from a given matrix. This function "batches" a given matrix
        of integers modulo the plaintext modulus into a plaintext element, and stores
        the result in the destination parameter. The input vector must have size at most equal
        to the degree of the polynomial modulus. The first half of the elements represent the
        first row of the matrix, and the second half represent the second row. The numbers
        in the matrix can be at most equal to the plaintext modulus for it to represent
        a valid plaintext.

        If the destination plaintext overlaps the input values in memory, the behavior of
        this function is undefined.

        @param[in] values The matrix of integers modulo plaintext modulus to batch
        @param[out] destination The plaintext polynomial to overwrite with the result
        @throws std::invalid_argument if values is too large
        */
        void encode(const std::vector<std::uint64_t> &values, PlaintextCuda &destination) const {
            Plaintext ret; host.encode(values, ret);
            destination = ret;
        }

        /**
        Creates a plaintext from a given matrix. This function "batches" a given matrix
        of integers modulo the plaintext modulus into a plaintext element, and stores
        the result in the destination parameter. The input vector must have size at most equal
        to the degree of the polynomial modulus. The first half of the elements represent the
        first row of the matrix, and the second half represent the second row. The numbers
        in the matrix can be at most equal to the plaintext modulus for it to represent
        a valid plaintext.

        If the destination plaintext overlaps the input values in memory, the behavior of
        this function is undefined.

        @param[in] values The matrix of integers modulo plaintext modulus to batch
        @param[out] destination The plaintext polynomial to overwrite with the result
        @throws std::invalid_argument if values is too large
        */

        void encode(const std::vector<std::int64_t> &values, PlaintextCuda &destination) const {
            Plaintext ret; host.encode(values, ret);
            destination = ret;
        }
        /**
        Inverse of encode. This function "unbatches" a given plaintext into a matrix
        of integers modulo the plaintext modulus, and stores the result in the destination
        parameter. The input plaintext must have degrees less than the polynomial modulus,
        and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
        for the encryption parameters. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext polynomial to unbatch
        @param[out] destination The matrix to be overwritten with the values in the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if pool is uninitialized
        */

        void decode(const PlaintextCuda &plain, std::vector<std::uint64_t> &destination) const {
            host.decode(plain.toHost(), destination);
        }

        /**
        Inverse of encode. This function "unbatches" a given plaintext into a matrix
        of integers modulo the plaintext modulus, and stores the result in the destination
        parameter. The input plaintext must have degrees less than the polynomial modulus,
        and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
        for the encryption parameters. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext polynomial to unbatch
        @param[out] destination The matrix to be overwritten with the values in the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is in NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        void decode(const PlaintextCuda &plain, std::vector<std::int64_t> &destination) const {
            host.decode(plain.toHost(), destination);
        }

        /**
        Returns the number of slots.
        */
        inline auto slotCount() const noexcept
        {
            return host.slotCount();
        }

    private:
        BatchEncoderCuda(const BatchEncoderCuda &copy) = delete;

        BatchEncoderCuda(BatchEncoderCuda &&source) = delete;

        BatchEncoderCuda &operator=(const BatchEncoderCuda &assign) = delete;

        BatchEncoderCuda &operator=(BatchEncoderCuda &&assign) = delete;
        
        BatchEncoder host;
    };
} // namespace seal
