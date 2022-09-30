#pragma once

#include <cstdint>
#include <array>
#include <stdexcept>

#include "utils/uintcore.h"


namespace troy {

    class Modulus {

        uint64_t value_ = 0;
        std::array<uint64_t, 3> const_ratio_ { {0,0,0} };
        std::size_t uint64_count_ = 0;
        int bit_count_ = 0;
        bool is_prime_ = false;

        void setValue(uint64_t value);

    public:
        

        /**
        Creates a Modulus instance. The value of the Modulus is set to
        the given value, or to zero by default.

        @param[in] value The integer modulus
        @throws std::invalid_argument if value is 1 or more than 61 bits
        */
        Modulus(std::uint64_t value = 0)
        {
            setValue(value);
        }

        /**
        Creates a new Modulus by copying a given one.

        @param[in] copy The Modulus to copy from
        */
        Modulus(const Modulus &copy) = default;

        /**
        Creates a new Modulus by copying a given one.

        @param[in] source The Modulus to move from
        */
        Modulus(Modulus &&source) = default;

        /**
        Copies a given Modulus to the current one.

        @param[in] assign The Modulus to copy from
        */
        Modulus &operator=(const Modulus &assign) = default;

        /**
        Moves a given Modulus to the current one.

        @param[in] assign The Modulus to move from
        */
        Modulus &operator=(Modulus &&assign) = default;

        /**
        Sets the value of the Modulus.

        @param[in] value The new integer modulus
        @throws std::invalid_argument if value is 1 or more than 61 bits
        */
        inline Modulus &operator=(std::uint64_t value)
        {
            setValue(value);
            return *this;
        }

        /**
        Returns the significant bit count of the value of the current Modulus.
        */
        inline int bitCount() const noexcept
        {
            return bit_count_;
        }

        /**
        Returns the size (in 64-bit words) of the value of the current Modulus.
        */
        inline std::size_t uint64Count() const noexcept
        {
            return uint64_count_;
        }

        /**
        Returns a const pointer to the value of the current Modulus.
        */
        inline const uint64_t *data() const noexcept
        {
            return &value_;
        }

        /**
        Returns the value of the current Modulus.
        */
        inline std::uint64_t value() const noexcept
        {
            return value_;
        }

        /**
        Returns the Barrett ratio computed for the value of the current Modulus.
        The first two components of the Barrett ratio are the floor of 2^128/value,
        and the third component is the remainder.
        */
        inline auto &constRatio() const noexcept
        {
            return const_ratio_;
        }

        /**
        Returns whether the value of the current Modulus is zero.
        */
        inline bool isZero() const noexcept
        {
            return value_ == 0;
        }

        /**
        Returns whether the value of the current Modulus is a prime number.
        */
        inline bool isPrime() const noexcept
        {
            return is_prime_;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator==(const Modulus &compare) const noexcept
        {
            return value_ == compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator==(std::uint64_t compare) const noexcept
        {
            return value_ == compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator!=(const Modulus &compare) const noexcept
        {
            return !operator==(compare);
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator!=(std::uint64_t compare) const noexcept
        {
            return !operator==(compare);
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator<(const Modulus &compare) const noexcept
        {
            return value_ < compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator<(std::uint64_t compare) const noexcept
        {
            return value_ < compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator<=(const Modulus &compare) const noexcept
        {
            return value_ <= compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator<=(std::uint64_t compare) const noexcept
        {
            return value_ <= compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator>(const Modulus &compare) const noexcept
        {
            return value_ > compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator>(std::uint64_t compare) const noexcept
        {
            return value_ > compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        inline bool operator>=(const Modulus &compare) const noexcept
        {
            return value_ >= compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator>=(std::uint64_t compare) const noexcept
        {
            return value_ >= compare;
        }

        // /**
        // Returns an upper bound on the size of the Modulus, as if it was
        // written to an output stream.

        // @param[in] compr_mode The compression mode
        // @throws std::invalid_argument if the compression mode is not supported
        // @throws std::logic_error if the size does not fit in the return type
        // */
        // inline std::streamoff save_size(
        //     compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     std::size_t members_size = Serialization::ComprSizeEstimate(util::add_safe(sizeof(value_)), compr_mode);

        //     return util::safe_cast<std::streamoff>(util::add_safe(sizeof(Serialization::SEALHeader), members_size));
        // }

        // /**
        // Saves the Modulus to an output stream. The output is in binary format
        // and not human-readable. The output stream must have the "binary" flag set.

        // @param[out] stream The stream to save the Modulus to
        // @param[in] compr_mode The desired compression mode
        // @throws std::invalid_argument if the compression mode is not supported
        // @throws std::logic_error if the data to be saved is invalid, or if
        // compression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff save(
        //     std::ostream &stream, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Save(
        //         std::bind(&Modulus::save_members, this, _1), save_size(compr_mode_type::none), stream, compr_mode,
        //         false);
        // }

        // /**
        // Loads a Modulus from an input stream overwriting the current Modulus.

        // @param[in] stream The stream to load the Modulus from
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff load(std::istream &stream)
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Load(std::bind(&Modulus::load_members, this, _1, _2), stream, false);
        // }

        // /**
        // Saves the Modulus to a given memory location. The output is in binary
        // format and not human-readable.

        // @param[out] out The memory location to write the Modulus to
        // @param[in] size The number of bytes available in the given memory location
        // @param[in] compr_mode The desired compression mode
        // @throws std::invalid_argument if out is null or if size is too small to
        // contain a SEALHeader, or if the compression mode is not supported
        // @throws std::logic_error if the data to be saved is invalid, or if
        // compression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff save(
        //     seal_byte *out, std::size_t size, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Save(
        //         std::bind(&Modulus::save_members, this, _1), save_size(compr_mode_type::none), out, size, compr_mode,
        //         false);
        // }

        // /**
        // Loads a Modulus from a given memory location overwriting the current
        // Modulus.

        // @param[in] in The memory location to load the Modulus from
        // @param[in] size The number of bytes available in the given memory location
        // @throws std::invalid_argument if in is null or if size is too small to
        // contain a SEALHeader
        // @throws std::logic_error if the data cannot be loaded by this version of
        // Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        // @throws std::runtime_error if I/O operations failed
        // */
        // inline std::streamoff load(const seal_byte *in, std::size_t size)
        // {
        //     using namespace std::placeholders;
        //     return Serialization::Load(std::bind(&Modulus::load_members, this, _1, _2), in, size, false);
        // }

        // /**
        // Reduces a given unsigned integer modulo this modulus.

        // @param[in] value The unsigned integer to reduce
        // @throws std::logic_error if the Modulus is zero
        // */
        // std::uint64_t reduce(std::uint64_t value) const;


    };


}