#include "modulus.h"
#include "utils/numth.h"
#include "utils/uintarith.h"
#include "utils/uintarithsmallmod.h"

namespace troy {

    void Modulus::setValue(uint64_t value) {
        if (value == 0) {            
            // Zero settings
            bit_count_ = 0;
            uint64_count_ = 1;
            value_ = 0;
            const_ratio_ = { { 0, 0, 0 } };
            is_prime_ = false;
        } else if ((value >> SEAL_MOD_BIT_COUNT_MAX != 0) || (value == 1)) {
            throw std::invalid_argument("Value can be at most 61-bit and cannot be 1.");
        } else {
            // All normal, compute const_ratio and set everything
            value_ = value;
            bit_count_ = util::getSignificantBitCount(value_);
            // Compute Barrett ratios for 64-bit words (barrett_reduce_128)
            uint64_t numerator[3]{ 0, 0, 1 };
            uint64_t quotient[3]{ 0, 0, 0 };
            // Use a special method to avoid using memory pool
            util::divideUint192Inplace(numerator, value_, quotient);
            const_ratio_[0] = quotient[0];
            const_ratio_[1] = quotient[1];
            // We store also the remainder
            const_ratio_[2] = numerator[0];
            uint64_count_ = 1;
            // Set the primality flag
            is_prime_ = util::isPrime(*this);
        }
    }

}