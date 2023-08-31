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
#include "Transaction.hpp"
#include "Hash.hpp"


namespace SPHINXBlock {
    class Block {
    public:
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
        std::string HashPrevBlock_;
        std::string HashMerkleRoot_;
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

        BlockHeader getBlockHeader() const {
            BlockHeader header;
            header.version = version_;
            header.HashPrevBlock = HashPrevBlock_;
            header.HashMerkleRoot = HashMerkleRoot_;
            header.signature = signature_;
            header.blockHeight = blockHeight_;
            header.timestamp = timestamp_;
            header.nonce = nonce_;
            header.difficulty = difficulty_;
            return header;
        }

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
