// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "rlwe.h"
#include "../publickey_cuda.cuh"
#include "../ciphertext_cuda.cuh"
#include "../publickey_cuda.cuh"
#include "../context_cuda.cuh"
#include "../secretkey_cuda.cuh"
#include <cstdint>

namespace troy
{
    namespace util
    {

        
        void encryptZeroAsymmetric(
            const PublicKeyCuda &public_key, const SEALContextCuda &context, ParmsID parms_id, bool is_ntt_form,
            CiphertextCuda &destination);

        void encryptZeroSymmetric(
            const SecretKeyCuda &secret_key, const SEALContextCuda &context, ParmsID parms_id, bool is_ntt_form,
            CiphertextCuda &destination);
    } // namespace util
} // namespace seal
