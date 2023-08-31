// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <string>

#include <cassert>
#include <stdexcept>

#include <tinyformat.h>
#include <util/strencodings.h>
#include <version.h>

#include <SphinxJS/jsonrpcpp/include/json.hpp>
#include <Script.hpp>
#include <Consensus/Asset.hpp>
#include <Hash.hpp>
#include "Transaction.hpp"


namespace SPHINXTx {

    // Convert COutPoint to a formatted string
    std::string COutPoint::ToString() const {
        return fmt::format("COutPoint({:.10}, {})", hash.ToString().substr(0, 10), n);
    }

    // Constructor for CTxIn
    CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
        : prevout(prevoutIn), scriptSig(scriptSigIn), nSequence(nSequenceIn) {}

    // Constructor for CTxIn with hashPrevTx
    CTxIn::CTxIn(SPHINXHash::SPHINX_256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
        : prevout(COutPoint(hashPrevTx, nOut)), scriptSig(scriptSigIn), nSequence(nSequenceIn) {}

    // Convert CTxIn to a formatted string
    std::string CTxIn::ToString() const {
        std::string str;
        str += fmt::format("CTxIn({}", prevout.ToString());
        if (prevout.IsNull())
            str += fmt::format(", coinbase {})", HexStr(scriptSig));
        else
            str += fmt::format(", scriptSig={})", HexStr(scriptSig).substr(0, 24));
        if (nSequence != SEQUENCE_FINAL)
            str += fmt::format(", nSequence={})", nSequence);
        return str;
    }

    // Constructor for CTxOut
    CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
        : nValue(nValueIn), scriptPubKey(scriptPubKeyIn) {}

    // Convert CTxOut to a formatted string
    std::string CTxOut::ToString() const {
        return fmt::format("CTxOut(nValue={}.{:08}, scriptPubKey={:.30})", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
    }

    // Default constructor and constructor from CTransaction
    CMutableTransaction::CMutableTransaction() : Version(CTransaction::CURRENT_VERSION), nLockTime(0) {}
    CMutableTransaction::CMutableTransaction(const CTransaction& tx)
        : vin(tx.vin), vout(tx.vout), Version(tx.Version), nLockTime(tx.nLockTime) {}

    // Calculate hash of the transaction
    SPHINXHash::SPHINX_256 CMutableTransaction::GetHash() const {
        // Serialize the object to JSON
        nlohmann::json jsonRepresentation = {
            {"Version", Version},
            {"vin", vin},
            {"vout", vout},
            {"nLockTime", nLockTime}
            // ... Add other members if needed
        };
        
        // Convert the JSON to a string and hash it
        std::string jsonString = jsonRepresentation.dump();
        return SPHINXHash::Hash(jsonString); // Assuming Hash is the function to calculate the hash
    }

    // Compute the hash of the transaction
    SPHINXHash::SPHINX_256 CTransaction::ComputeHash() const {
        // Serialize the object to JSON
        nlohmann::json jsonRepresentation = {
            {"Version", Version},
            {"vin", vin},
            {"vout", vout},
            {"nLockTime", nLockTime}
            // ... Add other members if needed
        };
        
        // Convert the JSON to a string and hash it
        std::string jsonString = jsonRepresentation.dump();
        return SPHINXHash::Hash(jsonString); // Assuming Hash is the function to calculate the hash
    }

    // Compute the witness hash of the transaction
    SPHINXHash::SPHINX_256 CTransaction::ComputeWitnessHash() const {
        if (!HasWitness()) {
            return hash;
        }
        
        // Serialize the object to JSON without witness data
        nlohmann::json jsonRepresentation = {
            {"Version", Version},
            {"vin", vin},
            {"vout", vout},
            {"nLockTime", nLockTime}
            // ... Add other members if needed
        };
        
        // Convert the JSON to a string and hash it
        std::string jsonString = jsonRepresentation.dump();
        return SPHINXHash::Hash(jsonString); // Assuming Hash is the function to calculate the hash
    }

    // Constructor for CTransaction from CMutableTransaction
    CTransaction::CTransaction(const CMutableTransaction& tx)
        : vin(tx.vin), vout(tx.vout), Version(tx.Version), nLockTime(tx.nLockTime), hash(ComputeHash()), m_witness_hash(ComputeWitnessHash()) {}

    // Move constructor for CTransaction from CMutableTransaction
    CTransaction::CTransaction(CMutableTransaction&& tx)
        : vin(std::move(tx.vin)), vout(std::move(tx.vout)), Version(tx.Version), nLockTime(tx.nLockTime), hash(ComputeHash()), m_witness_hash(ComputeWitnessHash()) {}

    // Calculate the total value out
    CAmount CTransaction::GetValueOut() const {
        CAmount nValueOut = 0;
        for (const auto& tx_out : vout) {
            if (!SPXRange(tx_out.nValue) || !SPXRange(nValueOut + tx_out.nValue))
                throw std::runtime_error(std::string(__func__) + ": value out of range");
            nValueOut += tx_out.nValue;
        }
        assert(SPXRange(nValueOut));
        return nValueOut;
    }

    // Calculate the total size of the transaction
    unsigned int CTransaction::GetTotalSize() const {
        return ::GetSerializeSize(*this, PROTOCOL_VERSION);
    }

    // Convert CTransaction to a formatted string
    std::string CTransaction::ToString() const {
        std::string str;
        str += fmt::format("CTransaction(hash={:.10}, ver={}, vin.size={}, vout.size={}, nLockTime={})\n",
            GetHash().ToString().substr(0, 10), Version, vin.size(), vout.size(), nLockTime);

        for (const auto& tx_in : vin)
            str += "    " + tx_in.ToString() + "\n";

        for (const auto& tx_out : vout)
            str += "    " + tx_out.ToString() + "\n";

        return str;
    }

} // namespace SPHINXTx
