// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <ctime>
#include <string>

#include "Block.hpp"
#include <Hash.hpp>
#include <SphinxJS/jsonrpcpp/include/json.hpp>

namespace SPHINXBlock {

    struct BlockHeader {
        uint32_t nVersion;
        std::string hashPrevBlock;
        std::string hashMerkleRoot;
        std::string signature;
        uint32_t blockHeight;
        std::time_t nTimestamp;
        uint32_t nNonce;
        uint32_t nDifficulty;

        SPHINXHash::SPHINX_256 GetHash() const {
            // Create a JSON representation of the object
            nlohmann::json jsonRepresentation = {
                {"version", nVersion},
                {"hashPrevBlock", hashPrevBlock},
                {"hashMerkleRoot", hashMerkleRoot},
                {"signature", signature},
                {"blockHeight", blockHeight},
                {"timestamp", nTimestamp},
                {"nonce", nNonce},
                {"difficulty", nDifficulty}
            };

            // Convert the JSON to a string
            std::string jsonString = jsonRepresentation.dump();

            // Calculate the hash using SPHINX_256 hash function
            return SPHINXHash::Hash(jsonString); // Assuming Hash is the function to calculate the hash
        }
    }

    std::string BlockHeader::ToString() const {
        std::stringstream ss;
        ss << "Block:\n";
        ss << "  Hash: " << GetHash() << "\n";
        ss << "  Version: 0x" << std::hex << version << "\n"; // Changed version_ to version
        ss << "  Prev Block: " << hashPrevBlock << "\n"; // Changed HashPrevBlock_ to hashPrevBlock
        ss << "  Merkle Root: " << hashMerkleRoot << "\n"; // Changed HashMerkleRoot_ to hashMerkleRoot
        ss << "  Time: " << timestamp << "\n"; // Changed timestamp_ to timestamp
        ss << "  Nonce: " << nonce << "\n"; // Changed nonce_ to nonce
        ss << "  Difficulty: " << difficulty << "\n"; // Changed difficulty_ to difficulty

        ss << "  Transactions: " << transactions.size() << "\n"; // Changed transactions_ to transactions

        for (const auto& tx : transactions) {
            ss << "  Transaction: " << tx << "\n";
        }

        return ss.str();
    }
} // namespace SPHINXBlock
