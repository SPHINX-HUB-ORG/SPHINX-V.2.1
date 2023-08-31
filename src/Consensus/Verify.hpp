// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINX_VERIFY_HPP
#define SPHINX_VERIFY_HPP

#include "Asset.hpp"

#include <stdint.h>
#include <vector>

namespace SPHINXVerify {

    /**
     * Check if transaction is considered final given a block height and block time.
     *
     * @param tx The transaction to check
     * @param nBlockHeight The block height
     * @param nBlockTime The block time
     * @return true if the transaction is final, false otherwise
     */
    bool IsFinalTx(const SPHINXTrx::Transaction &tx, int nBlockHeight, int64_t nBlockTime);

    /**
     * Calculate the sequence locks for a transaction.
     *
     * @param tx The transaction to calculate sequence locks for
     * @param flags Flags indicating sequence lock verification rules
     * @param prevHeights List of previous heights for each input
     * @param block The block index
     * @return A pair containing the calculated block height and previous block's median time past
     */
    std::pair<int, int64_t> CalculateSequenceLocks(const SPHINXTrx::Transaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block);

    /**
     * Evaluate the sequence locks for a given block.
     *
     * @param block The block index
     * @param lockPair The lock pair containing block height and median time past
     * @return true if sequence locks are satisfied, false otherwise
     */
    bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair);

    /**
     * Check if the sequence locks for a transaction are satisfied.
     *
     * @param tx The transaction to check
     * @param flags Flags indicating sequence lock verification rules
     * @param prevHeights List of previous heights for each input
     * @param block The block index
     * @return true if sequence locks are satisfied, false otherwise
     */
    bool SequenceLocks(const SPHINXTrx::Transaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block);

    /**
     * Get the count of legacy signature operations in a transaction.
     *
     * @param tx The transaction to count signature operations for
     * @return The number of legacy signature operations
     */
    unsigned int GetLegacySigOpCount(const SPHINXTrx::Transaction& tx);

    /**
     * Get the count of pay-to-script-hash signature operations in a transaction.
     *
     * @param tx The transaction to count signature operations for
     * @param inputs The cached coin view
     * @return The number of pay-to-script-hash signature operations
     */
    unsigned int GetP2SHSigOpCount(const SPHINXTrx::Transaction& tx, const CCoinsViewCache& inputs);

    /**
     * Get the total signature operation cost of a transaction.
     *
     * @param tx The transaction to calculate the cost for
     * @param inputs The cached coin view
     * @param flags Script verification flags
     * @return The total signature operation cost
     */
    int64_t GetTransactionSigOpCost(const SPHINXTrx::Transaction& tx, const CCoinsViewCache& inputs, uint32_t flags);

    class Consensus {
    public:
        /**
         * Check the inputs of a transaction.
         *
         * @param tx The transaction to check inputs for
         * @param state The transaction validation state
         * @param inputs The cached coin view
         * @param nSpendHeight The height at which the spending transaction is included
         * @param txfee The transaction fee
         * @return true if inputs are valid, false otherwise
         */
        static bool CheckTxInputs(const SPHINXTrx::Transaction& tx, TxValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee);
    };

} // namespace SPHINXVerify

#endif // SPHINX_VERIFY_HPP

