// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "ckks.h"
#include "plaintext_cuda.cuh"
#include "context_cuda.cuh"

namespace troy
{

    class CKKSEncoderCuda
    {

    public:
        /**
        Creates a CKKSEncoder instance initialized with the specified SEALContext.

        @param[in] context The SEALContext
        @throws std::invalid_argument if the encryption parameters are not valid
        @throws std::invalid_argument if scheme is not scheme_type::CKKS
        */
        CKKSEncoderCuda(const SEALContextCuda &context): host(context.host()) {}

        /**
        Encodes a vector of double-precision floating-point real or complex numbers
        into a plaintext polynomial. Append zeros if vector size is less than N/2.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @tparam T Vector value type (double or std::complex<double>)
        @param[in] values The vector of double-precision floating-point numbers
        (of type T) to encode
        @param[in] parms_id parms_id determining the encryption parameters to
        be used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if values has invalid size
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(const std::vector<std::complex<double>> &values, ParmsID parms_id, double scale, PlaintextCuda &destination)
        {
            Plaintext ret; host.encode(values, parms_id, scale, ret); destination = ret;
        }

        /**
        Encodes a vector of double-precision floating-point real or complex numbers
        into a plaintext polynomial. Append zeros if vector size is less than N/2.
        The encryption parameters used are the top level parameters for the given
        context. Dynamic memory allocations in the process are allocated from the
        memory pool pointed to by the given MemoryPoolHandle.

        @tparam T Vector value type (double or std::complex<double>)
        @param[in] values The vector of double-precision floating-point numbers
        (of type T) to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if values has invalid size
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(const std::vector<std::complex<double>> &values, double scale, PlaintextCuda &destination)
        {
            Plaintext ret; host.encode(values, scale, ret); destination = ret;
        }
        /**
        Encodes a double-precision floating-point real number into a plaintext
        polynomial. The number repeats for N/2 times to fill all slots. Dynamic
        memory allocations in the process are allocated from the memory pool
        pointed to by the given MemoryPoolHandle.

        @param[in] value The double-precision floating-point number to encode
        @param[in] parms_id parms_id determining the encryption parameters to be
        used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(double value, ParmsID parms_id, double scale, PlaintextCuda &destination){
            Plaintext ret; host.encode(value, parms_id, scale, ret); destination = ret;
        }

        /**
        Encodes a double-precision floating-point real number into a plaintext
        polynomial. The number repeats for N/2 times to fill all slots. The
        encryption parameters used are the top level parameters for the given
        context. Dynamic memory allocations in the process are allocated from
        the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] value The double-precision floating-point number to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(double value, double scale, PlaintextCuda &destination)
        {
            Plaintext ret; host.encode(value, scale, ret); destination = ret;
        }

        /**
        Encodes a double-precision complex number into a plaintext polynomial.
        Append zeros to fill all slots. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] value The double-precision complex number to encode
        @param[in] parms_id parms_id determining the encryption parameters to be
        used by the result plaintext
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(std::complex<double> value, ParmsID parms_id, double scale, PlaintextCuda &destination)
        {
            Plaintext ret; host.encode(value, parms_id, scale, ret); destination = ret;
        }

        /**
        Encodes a double-precision complex number into a plaintext polynomial.
        Append zeros to fill all slots. The encryption parameters used are the
        top level parameters for the given context. Dynamic memory allocations
        in the process are allocated from the memory pool pointed to by the
        given MemoryPoolHandle.

        @param[in] value The double-precision complex number to encode
        @param[in] scale Scaling parameter defining encoding precision
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if scale is not strictly positive
        @throws std::invalid_argument if encoding is too large for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encode(std::complex<double> value, double scale, PlaintextCuda &destination){
            Plaintext ret; host.encode(value, scale, ret); destination = ret;
        }

        /**
        Encodes an integer number into a plaintext polynomial without any scaling.
        The number repeats for N/2 times to fill all slots.
        @param[in] value The integer number to encode
        @param[in] parms_id parms_id determining the encryption parameters to be
        used by the result plaintext
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        */
        inline void encode(std::int64_t value, ParmsID parms_id, PlaintextCuda &destination)
        {
            Plaintext ret; host.encode(value, parms_id, ret); destination = ret;
        }

        /**
        Encodes an integer number into a plaintext polynomial without any scaling.
        The number repeats for N/2 times to fill all slots. The encryption
        parameters used are the top level parameters for the given context.

        @param[in] value The integer number to encode
        @param[out] destination The plaintext polynomial to overwrite with the
        result
        */
        inline void encode(std::int64_t value, PlaintextCuda &destination)
        {
            Plaintext ret; host.encode(value, ret); destination = ret;
        }

        /**
        Decodes a plaintext polynomial into double-precision floating-point
        real or complex numbers. Dynamic memory allocations in the process are
        allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @tparam T Vector value type (double or std::complex<double>)
        @param[in] plain The plaintext to decode
        @param[out] destination The vector to be overwritten with the values in
        the slots
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not in NTT form or is invalid
        for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void decode(const PlaintextCuda &plain, std::vector<std::complex<double>> &destination)
        {
            host.decode(plain.toHost(), destination);
        }
        /**
        Returns the number of complex numbers encoded.
        */
        inline std::size_t slotCount() const noexcept
        {
            return host.slotCount();
        }

    private:
        CKKSEncoder host;
    };
} // namespace seal
