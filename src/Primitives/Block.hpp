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

    struct CBlockHeader {
        uint32_t nVersion;
        std::string hashPrevBlock;
        std::string hashMerkleRoot;
        std::string signature;
        uint32_t nBlockHeight;
        std::time_t nTimestamp;
        uint32_t nNonce;
        uint32_t nDifficulty;

        // Constructor
        CBlockHeader() {
            SetNull();
        }

        // Serialization methods using nlohmann::json
        void to_json(nlohmann::json& j) const {
            j = nlohmann::json{{"version", nVersion}, {"hashPrevBlock", hashPrevBlock}, {"hashMerkleRoot", hashMerkleRoot}, {"timestamp", nTimestamp}, {"difficulty", nDifficulty}, {"nonce", nNonce}};
        }

        void from_json(const nlohmann::json& j) {
            nVersion = j["version"];
            hashPrevBlock = j["hashPrevBlock"];
            hashMerkleRoot = j["hashMerkleRoot"];
            nTimestamp = j["timestamp"];
            nDifficulty = j["difficulty"];
            nNonce = j["nonce"];
        }

        // Set all members to null values
        void SetNull() {
            nVersion = 0;
            hashPrevBlock.clear();
            hashMerkleRoot.clear();
            nTimestamp = 0;
            nDifficulty = 0;
            nNonce = 0;
        }

        // Check if the block is null
        bool IsNull() const {
            return (nDifficulty == 0);
        }

        // Get the hash of the block
        SPHINXHash::SPHINX_256 GetHash() const;

        // Get timestamp as NodeSeconds
        NodeSeconds GetNodeTimestamp() const {
            return NodeSeconds{std::chrono::seconds{nTimestamp}};
        }

        // Get block timestamp as int64_t
        int64_t GetBlockTimestamp() const {
            return static_cast<int64_t>(nTimestamp);
        }
    };

    struct CBlock : public CBlockHeader {
        std::vector<CTransactionRef> vtx;
        mutable bool fChecked;

        // Default constructor
        CBlock() {
            SetNull();
        }

        // Constructor with header
        CBlock(const CBlockHeader &header) {
            SetNull();
            *(static_cast<CBlockHeader*>(this)) = header;
        }

        // Serialization methods using nlohmann::json
        void to_json(nlohmann::json& j) const {
            to_json(static_cast<const CBlockHeader&>(*this)); // Call parent's to_json method
            j["vtx"] = vtx;
        }

        void from_json(const nlohmann::json& j) {
            from_json(j); // Call parent's from_json method
            vtx = j["vtx"];
        }

        // Set all members to null values
        void SetNull() {
            CBlockHeader::SetNull();
            vtx.clear();
            fChecked = false;
        }

        // Get the block header
        CBlockHeader GetBlockHeader() const {
            CBlockHeader block;
            block.nVersion = nVersion;
            block.hashPrevBlock = hashPrevBlock;
            block.hashMerkleRoot = hashMerkleRoot;
            block.nTimestamp = nTimestamp;
            block.nDifficulty = nDifficulty;
            block.nNonce = nNonce;
            return block;
        }

        // Convert the block to a string representation
        std::string ToString() const;
    };

    struct CBlockLocator {
        std::vector<SPHINXHash::SPHINX_256> vHave;

        // Default constructor
        CBlockLocator() {}

        // Constructor with vector
        explicit CBlockLocator(std::vector<SPHINXHash::SPHINX_256>&& have) : vHave(std::move(have)) {}

        // Serialization methods using nlohmann::json
        void to_json(nlohmann::json& j) const {
            j["vHave"] = vHave;
        }

        void from_json(const nlohmann::json& j) {
            vHave = j["vHave"];
        }

        // Set all members to null values
        void SetNull() {
            vHave.clear();
        }

        // Check if the block locator is null
        bool IsNull() const {
            return vHave.empty();
        }
    };

} // namespace SPHINXBlock




