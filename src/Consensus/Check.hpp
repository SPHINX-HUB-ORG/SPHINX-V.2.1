// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

#ifndef SPHINX_CHECK_HPP
#define SPHINX_CHECK_HPP

namespace SPHINXConsensus {
    class Transaction; // Forward declaration
    class TxValidationState; // Forward declaration
}

namespace SPHINXCheck {

    bool CheckTransaction(const SPHINXConsensus::Transaction& tx, SPHINXConsensus::TxValidationState& state);

} // namespace SPHINXCheck

#endif // SPHINX_CHECK_HPP
