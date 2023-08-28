// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINXBLOCK_HPP
#define SPHINXBLOCK_HPP

#include <cstdint>
#include <iostream>
#include <unordered_map>

#include <stdexcept>
#include <fstream> 
#include <iostream>
#include <ctime>
#include <string>
#include <vector>
#include <array>

#include "SphinxJS/jsonrpcpp/include/json.hpp"
#include "Params.hpp"
#include "MerkleBlock.hpp"
#include "Chain.hpp"


// Forward declaration of other classes used in this header
namespace SPHINXChain {
    class Chain;  // Assuming you have a Chain class
}

namespace SPHINXDb {
    class DistributedDb;  // Assuming you have a DistributedDb class
}

namespace SPHINXBlock {
    class Block {
    public:
        struct BlockHeader {
            uint32_t version;
            std::string previousHash;
            std::string merkleRoot;
            std::string signature;
            uint32_t blockHeight;
            std::time_t timestamp;
            uint32_t nonce;
            uint32_t difficulty;
        };

    private:
        int index;
        std::string previousHash_;
        std::string merkleRoot_;
        std::string signature_;
        uint32_t blockHeight_;
        std::time_t timestamp_;
        uint32_t nonce_;
        uint32_t difficulty_;
        uint32_t version_;
        std::vector<std::string> transactions_;
        SPHINXChain::Chain* blockchain_;
        const std::vector<std::string>& checkpointBlocks_;
        std::string storedMerkleRoot_;
        std::string storedSignature_;

    public:
        static const uint32_t MAX_BLOCK_SIZE = 1000;
        static const uint32_t MAX_TIMESTAMP_OFFSET = 600;

        int getIndex() const;
        BlockHeader getBlockHeader() const;

        Block(const std::string& prevBlockHash, const std::string& timestamp, const std::string& nonce, const std::vector<Transaction>& transactions, const std::string& version, const std::string& previousHash = "", int index = 0);

        uint32_t getVersion() const;
        void addTransaction(const std::string& transaction);
        std::string calculateBlockHash() const;
        std::string calculateMerkleRoot() const;
        void signMerkleRoot(const SPHINXPrivKey& privateKey, const std::string& merkleRoot);
        bool verifySignature(const SPHINXPubKey& publicKey) const;
        bool verifyMerkleRoot(const SPHINXPubKey& publicKey) const;
        bool verifyBlock(const SPHINXPubKey& publicKey) const;

        void setMerkleRoot(const std::string& merkleRoot);
        void setSignature(const std::string& signature);
        void setBlockHeight(uint32_t blockHeight);
        void setNonce(uint32_t nonce);
        void setDifficulty(uint32_t difficulty);
        void setTransactions(const std::vector<std::string>& transactions);

        std::string getPreviousHash() const;
        std::string getMerkleRoot() const;
        std::string getSignature() const;
        uint32_t getBlockHeight() const;
        std::time_t getTimestamp() const;
        uint32_t getNonce() const;
        uint32_t getDifficulty() const;
        std::vector<std::string> getTransactions() const;
        std::string getVersion() const;

        static nlohmann::json toJson(const BlockHeader& header);
        static BlockHeader fromJson(const nlohmann::json& headerJson);
        static std::string toString(const BlockHeader& header);

        bool save(const std::string& filename) const;
        static Block load(const std::string& filename);
        bool saveToDatabase(SPHINXDb::DistributedDb& distributedDb) const;
        static Block loadFromDatabase(const std::string& blockId, SPHINXDb::DistributedDb& distributedDb);

        std::string getStoredMerkleRoot() const;
        std::string getStoredSignature() const;
    };
} // namespace SPHINXBlock

#endif // SPHINX_BLOCK_HPP
