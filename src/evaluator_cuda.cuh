#pragma once

#include "context_cuda.cuh"
#include "ciphertext_cuda.cuh"
#include "kernelutils.cuh"

namespace troy {

    class EvaluatorCuda {

    public:

        EvaluatorCuda(SEALContextCuda& context): context_(context)
        {}

        void addInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2);
    
    private:

        EvaluatorCuda(const EvaluatorCuda&) = delete;
        EvaluatorCuda(EvaluatorCuda&&) = delete;

        EvaluatorCuda& operator=(const EvaluatorCuda&) = delete;
        EvaluatorCuda& operator=(EvaluatorCuda&&) = delete;

        SEALContextCuda context_;

    };

}