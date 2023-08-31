// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// The use of denominations like Giga, Mega, and Kilo for (SPX) serves a similar purpose as it does
// in other contexts: it makes values easier to understand, manage, and communicate. Here are a few reasons why
// such denominations are used:
    
    // 1). Clarity and Communication: Larger numbers can be challenging to interpret and compare at a
    // glance. By using prefixes like Giga, Mega, and Kilo, make it easier for individuals to
    // quickly understand the scale of the value being represented. It's much more intuitive to say
    // "1 GSPX" instead of "1,000,000,000 Smix."

    // 2). Ease of Use: Using denominations that are multiples of 10^3 (like Giga, Mega, Kilo) makes
    // calculations and conversions simpler. People are familiar with these prefixes from various
    // contexts, and they are accustomed to making mental estimations based on them.

    // 3). Flexibility in Transactions: Different denominations allow users to choose the appropriate
    // scale for their transactions. If someone wants to send a small amount, they can use smaller
    // denominations like Smix or kSPX. If they are dealing with a larger value, they can use higher
    // denominations.

    // 4). Consistency: Following a consistent naming convention with well-known prefixes from the 
    // metric system (Giga, Mega, Kilo) provides a standardized way of referring to different value 
    // scales. This makes it easier for users to understand the asset's value representation.
    // Psychological Impact: Larger denominations can have a psychological impact, influencing perceptions
    // of value and scarcity. This is similar to how prices ending in 99 cents can feel cheaper psychologically,
    // even though the difference is minimal.

// In the context of this asset, using Giga, Mega, and Kilo prefixes for denominations enhances usability,
// communication, and comprehension of the value being represented, making it more user-friendly and accessible
// to a wider audience.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#ifndef SPX_ASSET_HPP
#define SPX_ASSET_HPP

#include <cstdint>

namespace SPHINXAsset {

    /** Amount in Smix (Can be negative) */
    typedef int64_t CAmount;

    /**
        * 1 SPX (Symbolic Pixel) = 1,000,000,000,000,000,000 Smix (Smallest Symbolic Pixel)
        * 1 Gsmix (Giga-Smix)    = 1,000,000,000 Smix
        * 1 Msmix (Mega-Smix)    = 1,000,000 Smix
        * 1 ksmix (Kilo-Smix)    = 1,000 Smix
        * 1 Smix                 = The smallest unit
    **/

    /**
        * The biggest unit is 1 SPX (Symbolic Pixel). It's the highest denomination and represents 1 quintillion
        * (1,000,000,000,000,000,000) Smix (Smallest Symbolic Pixel).
        * The smallest unit is 1 Smix. It is the base unit and is the smallest denomination in system. All other
        * denominations are multiples of this base unit.
        * The denominations between the biggest and smallest units are as follows:
        * 1 GSPX (Giga-Smix) represents 1 billion Smix.
        * 1 MSPX (Mega-Smix) represents 1 million Smix.
        * 1 kSPX (Kilo-Smix) represents 1 thousand Smix.
    **/

    // Denominations of SPX
    static constexpr CAmount SPX  = 1000000000000000000;     // 1 SPX  = 1,000,000,000,000,000,000 Smix
    static constexpr CAmount GSPX = 1000000000000;           // 1 GSPX = 1,000,000,000 Smix
    static constexpr CAmount MSPX = 1000000000;              // 1 MSPX = 1,000,000 Smix
    static constexpr CAmount kSPX = 1000000;                 // 1 kSPX = 1,000 Smix
    static constexpr CAmount Smix = 1;                       // 1 Smix = 1 Smix

    /** Maximum supply of SPX */
    static constexpr CAmount MAX_SUPPLY = 50000000 * SPX;

    /** Check if an amount of SPX is within valid range */
    inline bool SPXRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_SUPPLY); }

} // namespace SPHINXAsset

#endif // SPX_ASSET_HPP
