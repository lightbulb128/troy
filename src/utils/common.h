#pragma once

#include <cstdint>
#include <type_traits>
#include <stdexcept>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

namespace troy { namespace util {

    constexpr int bytesPerUint64 = sizeof(std::uint64_t);

    constexpr int bitsPerNibble = 4;

    constexpr int bitsPerByte = 8;

    constexpr int bitsPerUint64 = bytesPerUint64 * bitsPerByte;

    constexpr int nibblesPerByte = 2;

    constexpr int nibblesPerUint64 = bytesPerUint64 * nibblesPerByte;

    inline int getSignificantBitCount(uint64_t value) {
        if (value == 0) return 0;
        unsigned long result = 0;
        result = 63UL - static_cast<unsigned long>(__builtin_clzll(value));
        return static_cast<int>(result + 1);
    }

    template <typename T, typename S, typename = std::enable_if_t<std::is_arithmetic<T>::value>,
        typename = std::enable_if_t<std::is_arithmetic<S>::value>>
    inline constexpr bool fits_in(S value) noexcept
    {
        bool result = false;

        if constexpr(std::is_same<T, S>::value)
        {
            // Same type
            result = true;
        }
        else if constexpr(sizeof(S) <= sizeof(T))
        {
            // Converting to bigger type
            if constexpr(std::is_integral<T>::value && std::is_integral<S>::value)
            {
                // Converting to at least equally big integer type
                if constexpr(
                    (std::is_unsigned<T>::value && std::is_unsigned<S>::value) ||
                    (!std::is_unsigned<T>::value && !std::is_unsigned<S>::value))
                {
                    // Both either signed or unsigned
                    result = true;
                }
                else if constexpr(std::is_unsigned<T>::value && std::is_signed<S>::value)
                {
                    // Converting from signed to at least equally big unsigned type
                    result = value >= 0;
                }
            }
            else if constexpr(std::is_floating_point<T>::value && std::is_floating_point<S>::value)
            {
                // Both floating-point
                result = true;
            }

            // Still need to consider integer-float conversions and all
            // unsigned to signed conversions
        }

        if constexpr(std::is_integral<T>::value && std::is_integral<S>::value)
        {
            // Both integer types
            if (value >= 0)
            {
                // Non-negative number; compare as std::uint64_t
                // Cannot use unsigned_leq with C++14 for lack of `if constexpr'
                result = static_cast<std::uint64_t>(value) <=
                            static_cast<std::uint64_t>((std::numeric_limits<T>::max)());
            }
            else
            {
                // Negative number; compare as std::int64_t
                result =
                    static_cast<std::int64_t>(value) >= static_cast<std::int64_t>((std::numeric_limits<T>::min)());
            }
        }
        else if constexpr(std::is_floating_point<T>::value)
        {
            // Converting to floating-point
            result = (static_cast<double>(value) <= static_cast<double>((std::numeric_limits<T>::max)())) &&
                        (static_cast<double>(value) >= -static_cast<double>((std::numeric_limits<T>::max)()));
        }
        else
        {
            // Converting from floating-point
            result = (static_cast<double>(value) <= static_cast<double>((std::numeric_limits<T>::max)())) &&
                        (static_cast<double>(value) >= static_cast<double>((std::numeric_limits<T>::min)()));
        }

        return result;
    }

    template <
        typename T, typename S, typename = std::enable_if_t<std::is_arithmetic<T>::value>,
        typename = std::enable_if_t<std::is_arithmetic<S>::value>>
    inline T safe_cast(S value)
    {
        if constexpr(!std::is_same<T, S>::value)
        {
            if (!fits_in<T>(value))
            {
                throw std::logic_error("cast failed");
            }
        }
        return static_cast<T>(value);
    }

    inline constexpr uint32_t reverseBits(uint32_t operand) noexcept {
        operand = (((operand & uint32_t(0xaaaaaaaa)) >> 1) | ((operand & uint32_t(0x55555555)) << 1));
        operand = (((operand & uint32_t(0xcccccccc)) >> 2) | ((operand & uint32_t(0x33333333)) << 2));
        operand = (((operand & uint32_t(0xf0f0f0f0)) >> 4) | ((operand & uint32_t(0x0f0f0f0f)) << 4));
        operand = (((operand & uint32_t(0xff00ff00)) >> 8) | ((operand & uint32_t(0x00ff00ff)) << 8));
        return static_cast<uint32_t>(operand >> 16) | static_cast<uint32_t>(operand << 16);
    }

    inline constexpr uint64_t reverseBits(uint64_t operand) noexcept {
        return static_cast<uint64_t>(reverseBits(static_cast<std::uint32_t>(operand >> 32))) |
                (static_cast<uint64_t>(reverseBits(static_cast<std::uint32_t>(operand & uint64_t(0xFFFFFFFF)))) << 32);
    }

    inline uint32_t reverseBits(uint32_t operand, int bit_count)
    {
        // Just return zero if bit_count is zero
        return (bit_count == 0) ? uint32_t(0)
                                : reverseBits(operand) >> (sizeof(uint32_t) * static_cast<std::size_t>(bitsPerByte) -
                                                            static_cast<std::size_t>(bit_count));
    }

    inline uint64_t reverseBits(uint64_t operand, int bit_count)
    {
        // Just return zero if bit_count is zero
        return (bit_count == 0) ? uint64_t(0)
                                : reverseBits(operand) >> (sizeof(uint64_t) * static_cast<std::size_t>(bitsPerByte) -
                                                            static_cast<std::size_t>(bit_count));
    }

    template <
        typename T, typename S, typename = std::enable_if_t<std::is_integral<T>::value>,
        typename = std::enable_if_t<std::is_integral<S>::value>>
    inline constexpr bool unsigned_eq(T in1, S in2) noexcept
    {
        return static_cast<std::uint64_t>(in1) == static_cast<std::uint64_t>(in2);
    }

    template <typename T, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
    inline constexpr T add_safe(T in1, T in2)
    {
        if constexpr(std::is_unsigned<T>::value)
        {
            if (in2 > (std::numeric_limits<T>::max)() - in1)
            {
                throw std::logic_error("unsigned overflow");
            }
        }
        else
        {
            if (in1 > 0 && (in2 > (std::numeric_limits<T>::max)() - in1))
            {
                throw std::logic_error("signed overflow");
            }
            else if (in1 < 0 && (in2 < (std::numeric_limits<T>::min)() - in1))
            {
                throw std::logic_error("signed underflow");
            }
        }
        return static_cast<T>(in1 + in2);
    }

    template <typename T, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
    inline T sub_safe(T in1, T in2)
    {
        if constexpr (std::is_unsigned<T>::value)
        {
            if (in1 < in2)
            {
                throw std::logic_error("unsigned underflow");
            }
        }
        else
        {
            if (in1 < 0 && (in2 > (std::numeric_limits<T>::max)() + in1))
            {
                throw std::logic_error("signed underflow");
            }
            else if (in1 > 0 && (in2 < (std::numeric_limits<T>::min)() + in1))
            {
                throw std::logic_error("signed overflow");
            }
        }
        return static_cast<T>(in1 - in2);
    }

    template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
    inline constexpr T mul_safe(T in1, T in2)
    {
        if constexpr(std::is_unsigned<T>::value)
        {
            if (in1 && (in2 > (std::numeric_limits<T>::max)() / in1))
            {
                throw std::logic_error("unsigned overflow");
            }
        }
        else
        {
            // Positive inputs
            if ((in1 > 0) && (in2 > 0) && (in2 > (std::numeric_limits<T>::max)() / in1))
            {
                throw std::logic_error("signed overflow");
            }
            // Negative inputs
            else if ((in1 < 0) && (in2 < 0) && ((-in2) > (std::numeric_limits<T>::max)() / (-in1)))
            {
                throw std::logic_error("signed overflow");
            }
            // Negative in1; positive in2
            else if ((in1 < 0) && (in2 > 0) && (in2 > (std::numeric_limits<T>::max)() / (-in1)))
            {
                throw std::logic_error("signed underflow");
            }
            // Positive in1; negative in2
            else if ((in1 > 0) && (in2 < 0) && (in2 < (std::numeric_limits<T>::min)() / in1))
            {
                throw std::logic_error("signed underflow");
            }
        }
        return static_cast<T>(in1 * in2);
    }
    

    template <
    typename T, typename S, typename = std::enable_if_t<std::is_integral<T>::value>,
    typename = std::enable_if_t<std::is_integral<S>::value>>
    inline constexpr bool unsigned_lt(T in1, S in2) noexcept
    {
        return static_cast<std::uint64_t>(in1) < static_cast<std::uint64_t>(in2);
    }

    template <typename T>
    inline T divideRoundUp(T value, T divisor) {
        return (add_safe(value, divisor - 1)) / divisor;
    }

}}