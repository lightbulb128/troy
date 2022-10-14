#pragma once

#include "context_cuda.cuh"
#include "ciphertext_cuda.cuh"
#include "kernelutils.cuh"

namespace troy {

    class EvaluatorCuda {

    public:

        EvaluatorCuda(SEALContextCuda& context): context_(context)
        {}

        void negateInplace(CiphertextCuda& encrypted) const;
        void addInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const;
        void subInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const;
        void multiplyInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const;
        void squareInplace(CiphertextCuda& encrypted) const;

    private:

        void bfvMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const;
        void ckksMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const;
        void bgvMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const;
        void bfvSquare(CiphertextCuda &encrypted) const;
        void ckksSquare(CiphertextCuda& encrypted) const;
        void bgvSquare(CiphertextCuda& encrypted) const;

        EvaluatorCuda(const EvaluatorCuda&) = delete;
        EvaluatorCuda(EvaluatorCuda&&) = delete;

        EvaluatorCuda& operator=(const EvaluatorCuda&) = delete;
        EvaluatorCuda& operator=(EvaluatorCuda&&) = delete;

        SEALContextCuda context_;

    };

}