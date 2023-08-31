// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SPHINXBLOCK_HPP
#define SPHINXBLOCK_HPP

#include <ctime>
#include <string>
#include <chrono>

#include "Transaction.hpp"
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

        // Constructor
        BlockHeader(){
            SetNull();
        }

        // Serialization methods using nlohmann::json
        void to_json(nlohmann::json& j) const {
            j = nlohmann::json{{"version", version}, {"hashPrevBlock", hashPrevBlock}, {"hashMerkleRoot", hashMerkleRoot}, {"timestamp", timestamp}, {"difficulty", difficulty}, {"nonce", nonce}};
        }

        void from_json(const nlohmann::json& j) {
            version = j["version"];
            hashPrevBlock = j["hashPrevBlock"];
            hashMerkleRoot = j["hashMerkleRoot"];
            timestamp = j["timestamp"];
            difficulty = j["difficulty"];
            nonce = j["nonce"];
        }

        // Set all members to null values
        void SetNull(){
            version = 0;
            hashPrevBlock.clear();
            hashMerkleRoot.clear();
            timestamp = 0;
            difficulty = 0;
            nonce = 0;
        }

        // Check if the block is null
        bool IsNull() const{
            return (difficulty == 0);
        }

        // Get the hash of the block
        SPHINXHash::SPHINX_256 GetHash() const;

        // Get timestamp as NodeSeconds
        NodeSeconds Timestamp() const{
            return NodeSeconds{std::chrono::seconds{timestamp}};
        }

        // Get block timestamp as int64_t
        int64_t GetBlockTimestamp() const{
            return static_cast<int64_t>(timestamp);
        }
    };

    struct Block : public BlockHeader {
        std::vector<CTransactionRef> vtx;
        mutable bool fChecked;

        // Default constructor
        Block(){
            SetNull();
        }

        // Constructor with header
        Block(const BlockHeader &header){
            SetNull();
            *(static_cast<BlockHeader*>(this)) = header;
        }

        // Serialization methods using nlohmann::json
        void to_json(nlohmann::json& j) const {
            to_json(static_cast<const BlockHeader&>(*this)); // Call parent's to_json method
            j["vtx"] = vtx;
        }

        void from_json(const nlohmann::json& j) {
            from_json(j); // Call parent's from_json method
            vtx = j["vtx"];
        }

        // Set all members to null values
        void SetNull(){
            BlockHeader::SetNull();
            vtx.clear();
            fChecked = false;
        }

        // Get the block header
        BlockHeader GetBlockHeader() const{
            BlockHeader block;
            block.version           = version;
            block.hashPrevBlock     = hashPrevBlock;
            block.hashMerkleRoot    = hashMerkleRoot;
            block.timestamp         = timestamp;
            block.difficulty        = difficulty;
            block.nonce             = nonce;
            return block;
        }

        // Convert the block to a string representation
        std::string ToString() const;
    };

    struct BlockLocator {
        std::vector<SPHINXHash::SPHINX_256> vHave;

        // Default constructor
        BlockLocator() {}

        // Constructor with vector
        explicit BlockLocator(std::vector<SPHINXHash::SPHINX_256>&& have) : vHave(std::move(have)) {}

        // Serialization methods using nlohmann::json
        void to_json(nlohmann::json& j) const {
            j["vHave"] = vHave;
        }

        void from_json(const nlohmann::json& j) {
            vHave = j["vHave"];
        }

        // Set all members to null values
        void SetNull(){
            vHave.clear();
        }

        // Check if the block locator is null
        bool IsNull() const{
            return vHave.empty();
        }
    };

} // namespace SPHINXBlock


