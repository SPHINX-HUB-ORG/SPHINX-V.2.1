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
        uint32_t version;
        std::string hashPrevBlock;
        std::string hashMerkleRoot;
        std::string signature;
        uint32_t blockHeight;
        std::time_t timestamp;
        uint32_t nonce;
        uint32_t difficulty;

        SPHINXHash::SPHINX_256 GetHash() const {
            // Create a JSON representation of the object
            nlohmann::json jsonRepresentation = {
                {"version", version},
                {"hashPrevBlock", hashPrevBlock},
                {"hashMerkleRoot", hashMerkleRoot},
                {"signature", signature},
                {"blockHeight", blockHeight},
                {"timestamp", timestamp},
                {"nonce", nonce},
                {"difficulty", difficulty}
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
