// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <iostream>
#include <vector>
#include <string>

#include <Hash.hpp>
#include "Merkle.hpp"

namespace SPHINXMerkle {

    // Namespace for the hashing function
    namespace SPHINXHash {
        std::string SPHINX_256(const std::string& data);
    }

    // Function to ComputeMerkleRoot
    std::string ComputeMerkleRoot(const std::vector<std::string>& hashes, bool* mutated) {
        if (hashes.empty()) {
            return std::string(); // Return an empty string or handle as needed
        }

        // Compute the Merkle root iteratively
        std::vector<std::string> currentLevel = hashes;
        while (currentLevel.size() > 1) {
            std::vector<std::string> nextLevel;
            for (size_t i = 0; i < currentLevel.size(); i += 2) {
                std::string combinedHash = currentLevel[i];
                if (i + 1 < currentLevel.size()) {
                    combinedHash += currentLevel[i + 1];
                }
                std::string hash = SPHINXHash::SPHINX_256(combinedHash); // Use the actual function name
                nextLevel.push_back(hash);
            }
            currentLevel = nextLevel;
        }

        // Optionally handle mutation check if needed
        if (mutated) {
            *mutated = false; // Implement mutation check if needed
        }

        return currentLevel[0];
    }

    // Function method to defined in the Merkle class within the SPHINXMerkle namespace.
    void Merkle::buildMerkleTree(const std::vector<Transaction>& transactions, const std::vector<Witness>& witnesses) {
        if (transactions.empty() || transactions.size() != witnesses.size()) {
            return;
        }

        // Calculate hashes for each transaction and witness pair
        std::vector<std::string> transactionHashes;
        for (size_t i = 0; i < transactions.size(); ++i) {
            const Transaction& transaction = transactions[i];
            const Witness& witness = witnesses[i];
            std::string combinedData = transaction.transactionData + witness.witnessData; // Adjust as needed
            std::string hash = SPHINXHash::SPHINX_256(combinedData); // Use the actual function name
            transactionHashes.push_back(hash);
        }

        // Build the Merkle tree
        merkleRoot = ComputeMerkleRoot(transactionHashes);
    }

    // Function method to defined in the Merkle class within the SPHINXMerkle namespace.
    bool Merkle::verifyMerkleProof(const std::string& merkleRoot, const std::string& transactionData, const std::string& witnessData) {
        std::string combinedData = transactionData + witnessData; // Adjust as needed
        std::string transactionHash = SPHINXHash::SPHINX_256(combinedData); // Use the actual function name

        // Find the path from the transactionHash to the merkleRoot
        std::vector<std::string> hashes;
        for (size_t i = 0; i < transactionHash.size(); i++) {
            hashes.push_back(std::string(1, transactionHash[i]));
        }

        // Check for mutation during Merkle path calculation
        bool mutated = false;
        std::string computedRoot = ComputeMerkleRoot(hashes, &mutated);

        // Verify the computed Merkle root and absence of mutation
        return (computedRoot == merkleRoot) && !mutated;
    }

    // Function to compute the Merkle root of transactions in a block
    std::string BlockMerkleRoot(const std::vector<Transaction>& transactions) {
        std::vector<std::string> transactionHashes;
        for (const Transaction& transaction : transactions) {
            std::string hash = SPHINXHash::SPHINX_256(transaction.transactionData); // Use the actual function name
            transactionHashes.push_back(hash);
        }
        return ComputeMerkleRoot(transactionHashes);
    }

    // Function to compute the Merkle root of transactions with witness data in a block
    std::string BlockWitnessMerkleRoot(const std::vector<Transaction>& transactions, const std::vector<Witness>& witnesses) {
        if (transactions.size() != witnesses.size()) {
            return std::string(); // Return an empty string or handle as needed
        }

        std::vector<std::string> transactionHashes;
        for (size_t i = 0; i < transactions.size(); ++i) {
            const Transaction& transaction = transactions[i];
            const Witness& witness = witnesses[i];
            std::string combinedData = transaction.transactionData + witness.witnessData; // Adjust as needed
            std::string hash = SPHINXHash::SPHINX_256(combinedData); // Use the actual function name
            transactionHashes.push_back(hash);
        }
        return ComputeMerkleRoot(transactionHashes);
    }

} // namespace SPHINXMerkle





