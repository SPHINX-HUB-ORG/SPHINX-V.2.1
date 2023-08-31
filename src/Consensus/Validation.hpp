// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef CONSENSUS_VALIDATION_H
#define CONSENSUS_VALIDATION_H

#include <string>
#include <vector>
#include <version.h>
#include "Consensus.hpp"
#include "Transaction.hpp"
#include "Block.hpp"


namespace SPHINXChainConsensus {

    /** Index marker for when no witness commitment is present in a coinbase transaction. */
    static constexpr int NO_WITNESS_COMMITMENT{-1};

    /** Minimum size of a witness commitment structure. Defined in BIP 141. **/
    static constexpr size_t MINIMUM_WITNESS_COMMITMENT{38};

    /** A "reason" why a transaction was invalid, suitable for determining whether the
     * provider of the transaction should be banned/ignored/disconnected/etc.
     */
    enum class TxValidationResult {
        TX_RESULT_UNSET = 0,     
        TX_CONSENSUS,           
        /**
         * Invalid by a change to consensus rules more recent than SegWit.
         * Currently unused as there are no such consensus rule changes, and any download
         * sources realistically need to support SegWit in order to provide useful data,
         * so differentiating between always-invalid and invalid-by-pre-SegWit-soft-fork
         * is uninteresting.
         */
        TX_RECENT_CONSENSUS_CHANGE,
        TX_INPUTS_NOT_STANDARD,   
        TX_NOT_STANDARD,          
        TX_MISSING_INPUTS,        
        TX_PREMATURE_SPEND, 
        /**
         * Transaction might have a witness prior to SegWit
         * activation, or witness may have been malleated (which includes
         * non-standard witnesses).
         */
        TX_WITNESS_MUTATED,
        /**
         * Transaction is missing a witness.
         */
        TX_WITNESS_STRIPPED,
        /**
         * Tx already in mempool or conflicts with a tx in the chain
         * (if it conflicts with another tx in mempool, we use MEMPOOL_POLICY as it failed to reach the RBF threshold)
         * Currently this is only used if the transaction already exists in the mempool or on chain.
         */
        TX_CONFLICT,
        TX_MEMPOOL_POLICY,       
        TX_NO_MEMPOOL,         
    };

    // Enum to represent validation result for blocks
    enum class BlockValidationResult {
        BLOCK_RESULT_UNSET = 0, 
        BLOCK_CONSENSUS,         
        /**
         * Invalid by a change to consensus rules more recent than SegWit.
         * Currently unused as there are no such consensus rule changes, and any download
         * sources realistically need to support SegWit in order to provide useful data,
         * so differentiating between always-invalid and invalid-by-pre-SegWit-soft-fork
         * is uninteresting.
         */
        BLOCK_RECENT_CONSENSUS_CHANGE,
        BLOCK_CACHED_INVALID,   
        BLOCK_INVALID_HEADER,   
        BLOCK_MUTATED,          
        BLOCK_MISSING_PREV,     
        BLOCK_INVALID_PREV,     
        BLOCK_TIME_FUTURE,      
        BLOCK_CHECKPOINT,      
        BLOCK_HEADER_LOW_WORK 
    };

    // Template for capturing information about validation
    template <typename Result>
    class ValidationState {
    private:
        Result m_result;
        std::string m_reject_reason;
        std::string m_debug_message;

    public:
        bool IsValid() const { return m_result == Result::TX_VALID || m_result == Result::BLOCK_VALID; }
        bool IsInvalid() const { return m_result == Result::TX_INVALID || m_result == Result::BLOCK_INVALID; }
        bool IsError() const { return m_result == Result::TX_RESULT_UNSET || m_result == Result::BLOCK_RESULT_UNSET; }
        Result GetResult() const { return m_result; }
        std::string GetRejectReason() const { return m_reject_reason; }
        std::string GetDebugMessage() const { return m_debug_message; }
        std::string ToString() const {
            if (IsValid()) {
                return "Valid";
            }
            if (!m_debug_message.empty()) {
                return m_reject_reason + ", " + m_debug_message;
            }
            return m_reject_reason;
        }

        bool SetResult(Result result, const std::string& reject_reason = "", const std::string& debug_message = "") {
            m_result = result;
            m_reject_reason = reject_reason;
            m_debug_message = debug_message;
            return IsValid();
        }
    };

    // Validation state for transactions
    class TxValidationState : public ValidationState<TxValidationResult> {};

    // Validation state for blocks
    class BlockValidationState : public ValidationState<BlockValidationResult> {};

    // Define your custom validation logic for transactions, blocks, etc.
    namespace Validation {

        // Validate a transaction based on your custom rules
        bool ValidateTransaction(const SPHINXChainConsensus::Transaction& tx) {
            // Your custom transaction validation logic here
            // For example:
            if (/* your validation logic */) {
                return TxValidationState().SetResult(TxValidationResult::TX_VALID);
            } else {
                return TxValidationState().SetResult(TxValidationResult::TX_INVALID, "Transaction is invalid");
            }
        }

        // Validate a block based on your custom rules
        bool ValidateBlock(const SPHINXChainConsensus::SPHINXBlock& block) {
            // Your custom block validation logic here
            // For example:
            if (/* your validation logic */) {
                return BlockValidationState().SetResult(BlockValidationResult::BLOCK_VALID);
            } else {
                return BlockValidationState().SetResult(BlockValidationResult::BLOCK_INVALID, "Block is invalid");
            }
        }

        /** Compute at which vout of the block's coinbase transaction the witness commitment occurs, or -1 if not found */
        inline int GetWitnessCommitmentIndex(const CBlock& block) {
            int commitpos = NO_WITNESS_COMMITMENT;
            if (!block.vtx.empty()) {
                for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
                    const CTxOut& vout = block.vtx[0]->vout[o];
                    if (vout.scriptPubKey.size() >= MINIMUM_WITNESS_COMMITMENT &&
                        vout.scriptPubKey[0] == OP_RETURN &&
                        vout.scriptPubKey[1] == 0x24 &&
                        vout.scriptPubKey[2] == 0xaa &&
                        vout.scriptPubKey[3] == 0x21 &&
                        vout.scriptPubKey[4] == 0xa9 &&
                        vout.scriptPubKey[5] == 0xed) {
                        commitpos = o;
                    }
                }
            }
            return commitpos;
        }
    }

} // namespace SPHINXChainConsensus

#endif // CONSENSUS_VALIDATION_H

