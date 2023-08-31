// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <stdexcept>
#include <fstream> 
#include <iostream>
#include <ctime>
#include <string>
#include <vector>
#include <array>
#include <map>

#include "Transaction.hpp"
#include "Block.hpp"
#include <Hash.hpp>
#include <SphinxJS/jsonrpcpp/include/json.hpp>
#include <Merkleblock.hpp>
#include <Chain.hpp>
#include "Db.hpp"
#include "Params.hpp"
#include "BlockManager.hpp"


namespace SPHINXBlock {
    class Block {    
    struct BlockHeader {
        uint32_t version;
        std::string HashPrevBlock;
        std::string HashMerkleRoot;
        std::string signature;
        uint32_t blockHeight;
        std::time_t timestamp;
        uint32_t nonce;
        uint32_t difficulty;
    };

    private:
        // Private member variables
        int index;
        std::string HashPrevBlock_;              // The hash of the previous block in the blockchain
        std::string HashMerkleRoot_;             // The Merkle root hash of the transactions in the block
        std::string signature_;                  // The signature of the block
        uint32_t blockHeight_;                   // The position of the block within the blockchain
        std::time_t timestamp_;                  // The time when the block was created
        uint32_t nonce_;                         // A random value used in the mining process to find a valid block hash
        uint32_t difficulty_;                    // A measure of how hard it is to find a valid block hash (mining difficulty)
        uint32_t version_;                       // Add this private member variable to store the version of the block
        std::vector<std::string> transactions_;  // The list of transactions included in the block
        SPHINXChain::Chain* blockchain_;         // A pointer to the blockchain (assuming SPHINXChain::Chain is a class)
        const std::vector<std::string>& checkpointBlocks_; // Reference to the list of checkpoint blocks

        // Private member variables to store Merkle root and signature
        std::string storedMerkleRoot_;
        std::string storedSignature_;

    public:
        static const uint32_t MAX_BLOCK_SIZE = 1000;       // Maximum allowed block size in number of transactions
        static const uint32_t MAX_TIMESTAMP_OFFSET = 600;  // Maximum allowed timestamp difference from current time

        // Add index function to the public section of Block class
        int getIndex() const {
            return index;
        }

        // Add a method to get the block header
        BlockHeader getBlockHeader() const {
            return SPHINXMerkleblock::getBlockHeader(previousHash_, std::to_string(timestamp_), std::to_string(nonce_), transactions_, version_);
        }
        
        // Constructor with version parameter and optional previousHash and index
        Block(const std::string& prevBlockHash, const std::string& timestamp, const std::string& nonce, const std::vector<Transaction>& transactions, const std::string& version, const std::string& previousHash = "", int index = 0)
            : index(index), previousHash_(previousHash), blockHeight_(0), nonce_(0), difficulty_(0), version_(version) {
            timestamp_ = std::time(nullptr); // Set the timestamp to the current time

            if (!previousHash.empty()) {
                this->previousHash_ = prevBlockHash;
            }

            this->timestamp_ = timestamp;
            this->nonce_ = nonce;
            this->transactions_ = transactions;
            this->version_ = version; // Set the version for this block

            // Merkle tree construction function is already implemented in "MerkleBlock.cpp"
            std::string merkleRoot = SPHINXMerkleBlock::constructMerkleTree(transactions);
            this->setMerkleRoot(merkleRoot); // Set the Merkle root for this block
        }

        // Getter function to retrieve the block version
        uint32_t getVersion() const {
            return version_;
        }

        // Function to add a transaction to the block
        void addTransaction(const std::string& transaction) {
            transactions_.push_back(transaction);
        }

        // Function to calculate the block hash
        std::string calculateBlockHash() const {
            // Concatenate all the data elements that uniquely identify the block
            std::string blockData = previousHash_ + std::to_string(timestamp_);

            for (const auto& transaction : transactions_) {
                blockData += transaction;
            }

            // Calculate the SPHINX_256 hash of the block data
            std::string blockHash = SPHINXHash::SPHINX_256(blockData);

            return blockHash;
        }

        // Function to calculate the Merkle root
        std::string calculateMerkleRoot() const {
            return SPHINXMerkleBlock::constructMerkleTree(transactions_);
        }

        // Function to sign the Merkle root with SPHINCS+ private key and store the signature
        void signMerkleRoot(const SPHINXPrivKey& privateKey, const std::string& merkleRoot) {
            // SPHINCS+ signing function is available in the "Sign.hpp"
            signature_ = SPHINXSign::sign_data(merkleRoot, privateKey);
            storedMerkleRoot_ = merkleRoot;
        }

        // Function to verify the block's signature with the given public key
        bool verifySignature(const SPHINXPubKey& publicKey) const {
            // Calculate the block hash
            std::string blockHash = calculateBlockHash();

            // Assuming the SPHINCS+ verification function is available in the library
            return SPHINXSign::verify_data(blockHash, signature_, publicKey);
        }

        // Function to verify the block's Merkle root with the given public key
        bool verifyMerkleRoot(const SPHINXPubKey& publicKey) const {
            return merkleBlock.verifyMerkleRoot(storedMerkleRoot_, transactions_);
        }

        // Function to verify the entire block with the given public key
        bool verifyBlock(const SPHINXPubKey& publicKey) const {
            // Call the verifySignature and verifyMerkleRoot functions
            return verifySignature(publicKey) && verifyMerkleRoot(publicKey);
        }

        // Setters and getters for the remaining member variables
        void setMerkleRoot(const std::string& merkleRoot) {
            merkleRoot_ = merkleRoot;
        }

        // Sets the signature of the block
        void setSignature(const std::string& signature) {
            signature_ = signature;
        }

        // Sets the block height (the position of the block within the blockchain)
        void setBlockHeight(uint32_t blockHeight) {
            blockHeight_ = blockHeight;
        }

        // Sets the nonce (a random value used in the mining process to find a valid block hash)
        void setNonce(uint32_t nonce) {
            nonce_ = nonce;
        }

        // Sets the difficulty level of mining (a measure of how hard it is to find a valid block hash)
        void setDifficulty(uint32_t difficulty) {
            difficulty_ = difficulty;
        }

        // Sets the transactions included in the block
        void setTransactions(const std::vector<std::string>& transactions) {
            transactions_ = transactions;
        }

        // Returns the previous hash (the hash of the previous block in the blockchain)
        std::string getPreviousHash() const {
            return previousHash_;
        }

        // Returns the Merkle root (the root hash of the Merkle tree constructed from the transactions)
        std::string getMerkleRoot() const {
            return merkleRoot_;
        }

        // Returns the signature of the block
        std::string getSignature() const {
            return signature_;
        }

        // Returns the block height (the position of the block within the blockchain)
        uint32_t getBlockHeight() const {
            return blockHeight_;
        }

        // Returns the timestamp (the time when the block was created)
        std::time_t getTimestamp() const {
            return timestamp_;
        }

        // Returns the nonce (a random value used in the mining process to find a valid block hash)
        uint32_t getNonce() const {
            return nonce_;
        }

        // Returns the difficulty level of mining (a measure of how hard it is to find a valid block hash)
        uint32_t getDifficulty() const {
            return difficulty_;
        }

        // Returns the transactions included in the block
        std::vector<std::string> getTransactions() const {
            return transactions_;
        }

        std::string getVersion() const {
            return version_;
        }

        // ! This is Block headers
        // Function to serialize BlockHeader to JSON format
        static nlohmann::json toJson(const BlockHeader& header) {
            nlohmann::json headerJson;

            headerJson["version"] = header.version;
            headerJson["previousHash"] = header.previousHash;
            headerJson["merkleRoot"] = header.merkleRoot;
            headerJson["signature"] = header.signature;
            headerJson["blockHeight"] = header.blockHeight;
            headerJson["timestamp"] = header.timestamp;
            headerJson["nonce"] = header.nonce;
            headerJson["difficulty"] = header.difficulty;

            return headerJson;
        }

        // Function to deserialize JSON to BlockHeader
        static BlockHeader fromJson(const nlohmann::json& headerJson) {
            BlockHeader header;

            header.version = headerJson["version"].get<uint32_t>();
            header.previousHash = headerJson["previousHash"].get<std::string>();
            header.merkleRoot = headerJson["merkleRoot"].get<std::string>();
            header.signature = headerJson["signature"].get<std::string>();
            header.blockHeight = headerJson["blockHeight"].get<uint32_t>();
            header.timestamp = headerJson["timestamp"].get<std::time_t>();
            header.nonce = headerJson["nonce"].get<uint32_t>();
            header.difficulty = headerJson["difficulty"].get<uint32_t>();

            return header;
        }

        // Function to print BlockHeader as a formatted string
        static std::string toString(const BlockHeader& header) {
            std::ostringstream oss;
            oss << "Block Header:\n";
            oss << "  Version: " << header.version << "\n";
            oss << "  Previous Hash: " << header.previousHash << "\n";
            oss << "  Merkle Root: " << header.merkleRoot << "\n";
            oss << "  Signature: " << header.signature << "\n";
            oss << "  Block Height: " << header.blockHeight << "\n";
            oss << "  Timestamp: " << header.timestamp << "\n";
            oss << "  Nonce: " << header.nonce << "\n";
            oss << "  Difficulty: " << header.difficulty << "\n";
            return oss.str();
        }

        bool save(const std::string& filename) const {
            // Convert the block object to JSON format
            nlohmann::json blockJson = toJson();

            // Open the output file stream
            std::ofstream outputFile(filename);
            if (outputFile.is_open()) {
                // Write the JSON data to the file with indentation
                outputFile << blockJson.dump(4);
                outputFile.close();
                return true; // Return true to indicate successful save
            }
            return false; // Return false to indicate failed save
        }

        static Block load(const std::string& filename) {
            // Open the input file stream
            std::ifstream inputFile(filename);
            if (inputFile.is_open()) {
                // Parse the JSON data from the file
                nlohmann::json blockJson;
                inputFile >> blockJson;
                inputFile.close();

                // Create a new block object and initialize it from the parsed JSON
                Block loadedBlock("");
                loadedBlock.fromJson(blockJson);
                return loadedBlock; // Return the loaded block
            }
            throw std::runtime_error("Failed to load block from file: " + filename); // Throw an exception if the file could not be opened
        }

        bool saveToDatabase(SPHINXDb::DistributedDb& distributedDb) const {
            // Convert the block object to JSON format
            nlohmann::json blockJson = toJson();

            // Get the block hash as the database key
            std::string blockId = getBlockHash();

            // Convert the JSON data to a string
            std::string blockData = blockJson.dump();

            // Save the block data to the distributed database
            distributedDb.saveData(blockData, blockId);

            return true;
        }

        static Block loadFromDatabase(const std::string& blockId, SPHINXDb::DistributedDb& distributedDb) {
            std::string blockData = distributedDb.loadData(blockId); // Load the block data from the distributed database
            nlohmann::json blockJson = nlohmann::json::parse(blockData); // Parse the JSON string

            Block loadedBlock("");
            loadedBlock.fromJson(blockJson); // Initialize the block from the JSON
            return loadedBlock;
        }

        // Getter functions to retrieve the stored Merkle root and signature
        std::string getStoredMerkleRoot() const {
            return storedMerkleRoot_;
        }

        std::string getStoredSignature() const {
            return storedSignature_;
        }
    };
} // namespace SPHINXBlock