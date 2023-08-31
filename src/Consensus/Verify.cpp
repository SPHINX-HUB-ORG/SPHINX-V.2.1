// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <chain.h>
#include <coins.h>

#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <util/check.h>
#include <util/moneystr.h>

#include "Asset.hpp"
#include "Validation.hpp"
#include <Transaction.hpp>
#include "verify.hpp"
#include "Consensus.hpp"


namespace SPHINXVerify {

    bool IsFinalTx(const SPHINXTrx::Transaction &tx, int nBlockHeight, int64_t nBlockTime) {
        // Check if the transaction's lock time is zero
        if (tx.nLockTime == 0) {
            return true;
        }

        // Check if the transaction's lock time is less than the block time or height
        if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime)) {
            return true;
        }

        // Check if all inputs' sequence numbers are set to SEQUENCE_FINAL
        for (const auto& txin : tx.vin) {
            if (txin.nSequence != SPHINXTrx::CTxIn::SEQUENCE_FINAL) {
                return false;
            }
        }

        return true;
    }

    std::pair<int, int64_t> CalculateSequenceLocks(const SPHINXTrx::Transaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block) {
    assert(prevHeights.size() == tx.vin.size());

        int nMinHeight = -1;
        int64_t nMinTime = -1;

        bool fEnforceBIP68 = (flags & LOCKTIME_VERIFY_SEQUENCE) && (static_cast<uint32_t>(tx.nVersion) >= 2);

        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const SPHINXTrx::CTxIn& txin = tx.vin[txinIndex];
            int nCoinHeight = prevHeights[txinIndex];

            if (txin.nSequence & SPHINXTrx::CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
                // The height of this input is not relevant for sequence locks
                prevHeights[txinIndex] = 0;
                continue;
            }

            if (txin.nSequence & SPHINXTrx::CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
                int64_t nCoinTime = (nCoinHeight == 0) ? 0 : block.GetAncestor(nCoinHeight - 1)->GetMedianTimePast();
                nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & SPHINXTrx::CTxIn::SEQUENCE_LOCKTIME_MASK) << SPHINXTrx::CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
            } else {
                nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & SPHINXTrx::CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
            }
        }

        return std::make_pair(nMinHeight, nMinTime);
    }


    bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair) {
    assert(block.pprev);

        int64_t nBlockTime = block.pprev->GetMedianTimePast();

        if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime) {
            return false; // Sequence locks are not satisfied
        }

        return true; // Sequence locks are satisfied
    }

    bool SequenceLocks(const SPHINXTrx::Transaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block) {
        std::pair<int, int64_t> lockPair = CalculateSequenceLocks(tx, flags, prevHeights, block);
        return EvaluateSequenceLocks(block, lockPair);
    }

    unsigned int GetLegacySigOpCount(const SPHINXTrx::Transaction& tx) {
    unsigned int nSigOps = 0;
        
        // Loop through the inputs and count the signature operations in their scriptSigs
        for (const auto& txin : tx.vin) {
            nSigOps += txin.scriptSig.GetSigOpCount(false);
        }
        
        // Loop through the outputs and count the signature operations in their scriptPubKeys
        for (const auto& txout : tx.vout) {
            nSigOps += txout.scriptPubKey.GetSigOpCount(false);
        }
        
        return nSigOps;
    }

    unsigned int GetP2SHSigOpCount(const SPHINXTrx::Transaction& tx, const CCoinsViewCache& inputs) {
        if (tx.IsCoinBase())
            return 0;

        unsigned int nSigOps = 0;
        
        for (const auto& txin : tx.vin) {
            const Coin& coin = inputs.AccessCoin(txin.prevout);
            assert(!coin.IsSpent());
            const CTxOut &prevout = coin.out;

            if (prevout.scriptPubKey.IsPayToScriptHash())
                nSigOps += prevout.scriptPubKey.GetSigOpCount(txin.scriptSig);
        }
        
        return nSigOps;
    }


    int64_t GetTransactionSigOpCost(const SPHINXTrx::Transaction& tx, const CCoinsViewCache& inputs, uint32_t flags) {
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

        if (tx.IsCoinBase())
            return nSigOps;

        if (flags & SCRIPT_VERIFY_P2SH) {
            nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
        }

        for (const auto& txin : tx.vin) {
            const Coin& coin = inputs.AccessCoin(txin.prevout);
            assert(!coin.IsSpent());
            const CTxOut &prevout = coin.out;
            
            nSigOps += CountWitnessSigOps(txin.scriptSig, prevout.scriptPubKey, &txin.scriptWitness, flags);
        }
        
        return nSigOps;
    }


    bool Consensus::CheckTxInputs(const SPHINXTrx::Transaction& tx, TxValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee) {
    // Validate the transaction inputs and perform necessary checks
    // You can access tx.data, tx.signature, tx.publicKey to perform checks

    // Check if the actual inputs are available in the inputs cache
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent",
                     strprintf("%s: inputs missing/spent", __func__));
    }

    CAmount nValueIn = 0;
    for (const auto& txin : tx.vin) {
        const Coin& coin = inputs.AccessCoin(txin.prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < SPHINXConsensus::COINBASE_MATURITY) {
            return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
        }
    }

    const CAmount value_out = tx.GetValueOut();
        if (nValueIn < value_out) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout",
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
        }

        // Calculate transaction fee
        const CAmount txfee_aux = nValueIn - value_out;
        if (!MoneyRange(txfee_aux)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-outofrange");
        }

        txfee = txfee_aux;
        return true;
    }

} // namespace SPHINX_VERIFY