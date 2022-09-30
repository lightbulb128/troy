#pragma once

#include <cstdint>
#include <vector>

namespace troy {

enum class SchemeType: uint8_t {
    none = 0x0,
    ckks = 0x2
};

class EncryptionParameters {

private:
    SchemeType scheme_;
    size_t poly_modulus_degree_ = 0;
    // std::vector<Modulus> coeff_modulus_{};
    // Modulus plain_modulus_{};

};

}