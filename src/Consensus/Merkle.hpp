// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef MERKLE_HPP
#define MERKLE_HPP

#include <vector>
#include <string>
#include <Hash.hpp>
#include <Block.hpp>


namespace SPHINXMerkle {

    // Define the Transaction and Witness structures if not already defined
    struct Transaction {
        std::string transactionData; // Define your Transaction data structure here
    };

    struct Witness {
        std::string witnessData; // Define your Witness data structure here
    };

    class Merkle {
    public:
        // Constructor and other member functions if needed
        
        // Function to build a Merkle tree
        void buildMerkleTree(const std::vector<Transaction>& transactions, const std::vector<Witness>& witnesses);

        // Function to verify a Merkle proof
        bool verifyMerkleProof(const std::string& merkleRoot, const std::string& transactionData, const std::string& witnessData);

        // Function to compute the Merkle root of transactions in a block
        std::string BlockMerkleRoot(const std::vector<Transaction>& transactions);

        // Function to compute the Merkle root of transactions with witness data in a block
        std::string BlockWitnessMerkleRoot(const std::vector<Transaction>& transactions, const std::vector<Witness>& witnesses);

    private:
        // Add private member variables if needed
        
        // Namespace for the hashing function
        namespace SPHINXHash {
            std::string SPHINX_256(const std::string& data);
        }
        
        // Placeholder for the ComputeMerkleRoot function
        std::string ComputeMerkleRoot(const std::vector<std::string>& hashes, bool* mutated);
        
        // Add private member functions if needed
    };

} // namespace SPHINXMerkle

#endif // SPHINX_MERKLE_HPP
