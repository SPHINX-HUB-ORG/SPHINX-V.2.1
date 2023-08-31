// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

#include "Asset.hpp"
#include "Check.hpp"
#include "Validation.hpp"
#include <Transaction.hpp>

namespace SPHINXCheck {

    bool CheckTransaction(const SPHINXTrx::Transaction& tx, SPHINXConsensus::TxValidationState& state)
    {
        // Basic checks that don't depend on any context
        if (tx.vin.empty())
            return state.Invalid(SPHINXConsensus::TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
        if (tx.vout.empty())
            return state.Invalid(SPHINXConsensus::TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");

        // Size limits
        if (GetTransactionSize(tx) > SPHINXConsensus::MAX_TRANSACTION_SIZE)
            return state.Invalid(SPHINXConsensus::TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");

        // Check for negative or overflow output values
        SPHINXConsensus::CAmount nValueOut = 0;
        for (const auto& txout : tx.vout)
        {
            if (txout.value < 0)
                return state.Invalid(SPHINXConsensus::TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
            if (txout.value > SPHINXConsensus::SPHINXAsset::MAX_MONEY)
                return state.Invalid(SPHINXConsensus::TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
            nValueOut += txout.value;
            if (!SPHINXConsensus::SPHINXAsset::SPXRange(nValueOut))
                return state.Invalid(SPHINXConsensus::TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
        }

        // Check for duplicate inputs
        std::set<SPHINXConsensus::SPHINXAsset::OutPoint> vInOutPoints;
        for (const auto& txin : tx.vin) {
            if (!vInOutPoints.insert(txin.prevout).second)
                return state.Invalid(SPHINXConsensus::TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
        }

        if (tx.IsCoinbase())
        {
            if (tx.vin[0].scriptSig.size() < SPHINXConsensus::SPHINXAsset::MIN_COINBASE_SCRIPT_SIZE ||
                tx.vin[0].scriptSig.size() > SPHINXConsensus::SPHINXAsset::MAX_COINBASE_SCRIPT_SIZE)
                return state.Invalid(SPHINXConsensus::TxValidationResult::TX_CONSENSUS, "bad-cb-length");
        }
        else
        {
            for (const auto& txin : tx.vin)
                if (txin.prevout.IsNull())
                    return state.Invalid(SPHINXConsensus::TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
        }

        return true;
    }

} // namespace SPHINXCheck