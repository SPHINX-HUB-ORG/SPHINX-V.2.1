// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_TRX_HPP
#define SPHINX_TRX_HPP

#include <ctime>
#include <iostream>
#include <sstream>

#include <cstdint>
#include <vector>
#include <limits>
#include <string>
#include <algorithm>
#include <numeric>
#include <memory>
#include <iostream>

#include <prevector.h>

#include <Consensus/Asset.hpp>
#include <script.hpp>
#include <serialize.h>
#include <Hash.hpp"


namespace SPHINXTx {

    // Constants
    constexpr int SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000;

    // Forward Declarations
    class COutPoint;
    class CTxIn;
    class CTxOut;
    struct CMutableTransaction;
    class CTransaction;

    // Helper Functions
    inline bool operator!=(const COutPoint& a, const COutPoint& b);

    // Class Definitions
    class COutPoint {
    public:
        SPHINXHash::SPHINX_256 hash; // Replaced uint256 with SPHINXHash::SPHINX_256
        uint32_t n;

        static constexpr uint32_t NULL_INDEX = std::numeric_limits<uint32_t>::max();

        COutPoint() : n(NULL_INDEX) {}
        COutPoint(const SPHINXHash::SPHINX_256& hashIn, uint32_t nIn) : hash(hashIn), n(nIn) {}

        // Methods
        void SetNull() { hash.SetNull(); n = NULL_INDEX; }
        bool IsNull() const { return (hash.IsNull() && n == NULL_INDEX); }

        // Operators
        friend bool operator<(const COutPoint& a, const COutPoint& b);
        friend bool operator==(const COutPoint& a, const COutPoint& b);
        friend bool operator!=(const COutPoint& a, const COutPoint& b);

        std::string ToString() const;
    };

    class CTxIn {
    public:
        COutPoint prevout;
        CScript scriptSig;
        uint32_t nSequence;
        CScriptWitness scriptWitness;

        // Constants
        static const uint32_t SEQUENCE_FINAL = 0xffffffff;
        static const uint32_t MAX_SEQUENCE_NONFINAL;

        // Flags
        static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG;
        static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG;
        static const uint32_t SEQUENCE_LOCKTIME_MASK;
        static const int SEQUENCE_LOCKTIME_GRANULARITY;

        // Constructors
        CTxIn();
        explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn = CScript(), uint32_t nSequenceIn = SEQUENCE_FINAL);
        CTxIn(SPHINXHash::SPHINX_256 hashPrevTx, uint32_t nOut, CScript scriptSigIn = CScript(), uint32_t nSequenceIn = SEQUENCE_FINAL);

        // Operators
        friend bool operator==(const CTxIn& a, const CTxIn& b);
        friend bool operator!=(const CTxIn& a, const CTxIn& b);

        std::string ToString() const;
    };

    class CTxOut {
    public:
        CAmount nValue;
        CScript scriptPubKey;

        CTxOut();
        CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

        // Operators
        friend bool operator==(const CTxOut& a, const CTxOut& b);
        friend bool operator!=(const CTxOut& a, const CTxOut& b);

        std::string ToString() const;
    };

    struct CMutableTransaction {
        std::vector<CTxIn> vin;
        std::vector<CTxOut> vout;
        int32_t nVersion;
        uint32_t nLockTime;

        explicit CMutableTransaction();
        explicit CMutableTransaction(const CTransaction& tx);

        // Serialize CMutableTransaction to JSON
        template <typename Stream>
        void Serialize(Stream& s) const {
            nlohmann::json jsonOutput;
            to_json(jsonOutput, *this);
            s << jsonOutput.dump();
        }

        // Deserialize CMutableTransaction from JSON
        template <typename Stream>
        void Unserialize(Stream& s) {
            nlohmann::json jsonInput;
            s >> jsonInput;
            from_json(jsonInput, *this);
        }

        // Deserialize constructor for CMutableTransaction from JSON
        template <typename Stream>
        CMutableTransaction(deserialize_type, Stream& s) {
            Unserialize(s);
        }

        SPHINXHash::SPHINX_256 GetHash() const;

        bool HasWitness() const;
    };

    class CTransaction {
    public:
        static const int32_t CURRENT_VERSION = 2;

        const std::vector<CTxIn> vin;
        const std::vector<CTxOut> vout;
        const int32_t nVersion;
        const uint32_t nLockTime;

        // Constructors
        explicit CTransaction(const CMutableTransaction& tx);
        explicit CTransaction(CMutableTransaction&& tx);

        // Serialization using nlohmann::json
        template <typename Stream>
        void Serialize(Stream& s) const {
            nlohmann::json jsonOutput;
            
            // Populate jsonOutput with relevant data from *this
            
            s << jsonOutput.dump();
        }

        // Deserialization using nlohmann::json
        template <typename Stream>
        CTransaction(deserialize_type, Stream& s) {
            nlohmann::json jsonInput;
            s >> jsonInput;

            // Extract data from jsonInput and construct a CMutableTransaction object
            CMutableTransaction mutableTx(deserialize, jsonInput);

            // Construct a CTransaction using the CMutableTransaction
            *this = CTransaction(mutableTx);
        }

        // Methods
        bool IsNull() const;
        const SPHINXHash::SPHINX_256& GetHash() const;
        const SPHINXHash::SPHINX_256& GetWitnessHash() const;
        CAmount GetValueOut() const;
        unsigned int GetTotalSize() const;
        bool IsCoinBase() const;
        bool HasWitness() const;

        // Operators
        friend bool operator==(const CTransaction& a, const CTransaction& b);
        friend bool operator!=(const CTransaction& a, const CTransaction& b);

        std::string ToString() const;
    };

}; // namespace SPHINXTx

#endif // TRANSACTION_HPP



