#pragma once

#include "context_cuda.cuh"
#include "plaintext_cuda.cuh"
#include "ciphertext_cuda.cuh"
#include "kernelutils.cuh"
#include "relinkeys_cuda.cuh"
#include <stdexcept>

namespace troy {

    class EvaluatorCuda {

    public:

        EvaluatorCuda(SEALContextCuda& context): context_(context)
        {}

        void negateInplace(CiphertextCuda& encrypted) const;

        inline void negate(const CiphertextCuda &encrypted, CiphertextCuda &destination) const
        {
            destination = encrypted;
            negateInplace(destination);
        }
        void addInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const;
        
        inline void add(const CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2, CiphertextCuda &destination) const
        {
            if (&encrypted2 == &destination)
            {
                addInplace(destination, encrypted1);
            }
            else
            {
                destination = encrypted1;
                addInplace(destination, encrypted2);
            }
        }
        
        void addMany(const std::vector<CiphertextCuda> &encrypteds, CiphertextCuda &destination) const {
            if (encrypteds.empty())
            {
                throw std::invalid_argument("encrypteds cannot be empty");
            }
            for (size_t i = 0; i < encrypteds.size(); i++)
            {
                if (&encrypteds[i] == &destination)
                {
                    throw std::invalid_argument("encrypteds must be different from destination");
                }
            }

            destination = encrypteds[0];
            for (size_t i = 1; i < encrypteds.size(); i++)
            {
                addInplace(destination, encrypteds[i]);
            }
        }

        void subInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const;
        
        
        inline void sub(const CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2, CiphertextCuda &destination) const
        {
            if (&encrypted2 == &destination)
            {
                subInplace(destination, encrypted1);
                negateInplace(destination);
            }
            else
            {
                destination = encrypted1;
                subInplace(destination, encrypted2);
            }
        }

        void multiplyInplace(CiphertextCuda& encrypted1, const CiphertextCuda& encrypted2) const;
        
        
        inline void multiply(
            const CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2, CiphertextCuda &destination) const
        {
            if (&encrypted2 == &destination)
            {
                multiplyInplace(destination, encrypted1);
            }
            else
            {
                destination = encrypted1;
                multiplyInplace(destination, encrypted2);
            }
        }

        void squareInplace(CiphertextCuda& encrypted) const;

        inline void relinearizeInplace(
            CiphertextCuda &encrypted, const RelinKeysCuda &relin_keys) const
        {
            relinearizeInternal(encrypted, relin_keys, 2);
        }

        
        inline void square(
            const CiphertextCuda &encrypted, CiphertextCuda &destination) const
        {
            destination = encrypted;
            squareInplace(destination);
        }

        
        inline void relinearize(
            const CiphertextCuda &encrypted, const RelinKeys &relin_keys, CiphertextCuda &destination) const
        {
            destination = encrypted;
            relinearizeInplace(destination, relin_keys);
        }



        void modSwitchToNext(
            const CiphertextCuda &encrypted, CiphertextCuda &destination) const;


        inline void modSwitchToNextInplace(
            CiphertextCuda &encrypted) const
        {
            modSwitchToNext(encrypted, encrypted);
        }

        inline void modSwitchToNextInplace(PlaintextCuda &plain) const
        {
            modSwitchDropToNext(plain);
        }


        inline void modSwitchToNext(const PlaintextCuda &plain, PlaintextCuda &destination) const
        {
            destination = plain;
            modSwitchToNextInplace(destination);
        }


        void modSwitchToInplace(
            CiphertextCuda &encrypted, ParmsID parms_id) const;


        inline void modSwitchTo(
            const CiphertextCuda &encrypted, ParmsID parms_id, CiphertextCuda &destination) const
        {
            destination = encrypted;
            modSwitchToInplace(destination, parms_id);
        }


        void modSwitchToInplace(PlaintextCuda &plain, ParmsID parms_id) const;


        inline void modSwitchTo(const PlaintextCuda &plain, ParmsID parms_id, PlaintextCuda &destination) const
        {
            destination = plain;
            modSwitchToInplace(destination, parms_id);
        }

    private:

        void bfvMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const;
        void ckksMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const;
        void bgvMultiply(CiphertextCuda &encrypted1, const CiphertextCuda &encrypted2) const;
        void bfvSquare(CiphertextCuda &encrypted) const;
        void ckksSquare(CiphertextCuda& encrypted) const;
        void bgvSquare(CiphertextCuda& encrypted) const;

        
        void relinearizeInternal(CiphertextCuda &encrypted, const RelinKeysCuda &relin_keys, std::size_t destination_size) const;

        void switchKeyInplace(
            CiphertextCuda &encrypted, util::ConstDevicePointer<uint64_t> target_iter, const KSwitchKeysCuda &kswitch_keys,
            std::size_t key_index) const;


        EvaluatorCuda(const EvaluatorCuda&) = delete;
        EvaluatorCuda(EvaluatorCuda&&) = delete;

        EvaluatorCuda& operator=(const EvaluatorCuda&) = delete;
        EvaluatorCuda& operator=(EvaluatorCuda&&) = delete;

        void modSwitchScaleToNext(
            const CiphertextCuda &encrypted, CiphertextCuda &destination) const;

        void modSwitchDropToNext(const CiphertextCuda &encrypted, CiphertextCuda &destination) const;
        void modSwitchDropToNext(PlaintextCuda &plain) const;

        SEALContextCuda context_;

    };

}