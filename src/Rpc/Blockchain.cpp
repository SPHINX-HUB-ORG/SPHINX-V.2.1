// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>

// Available Library
#include <Consensus/Asset.hpp>
#include <Consensus/Params.hpp>
#include <Consensus/Validation.hpp>
#include <Hash.hpp>
#include <Blockchain.hpp>
#include "jsonrpcpp/include/json.hpp"
#include "jsonrpccpp/server.h"
#include <sync.h>
#include <chain.h>
#include <chainparams.h>


// Not Available Library
#include <blockfilter.h>
#include <coins.h>

#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <kernel/coinstats.h>
#include <logging/timer.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/utxo_snapshot.h>
#include <primitives/transaction.h>

#include <rpc/server_util.h>
#include <rpc/util.h>

#include <script/descriptor.h>
#include <streams.h>

#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>
#include <warnings.h>

#include <stdint.h>


namespace SPHINXBlockchain {
    // Includes necessary namespaces for kernel and node.
    using namespace kernel;
    // Includes necessary namespaces for node.
    using namespace node;
    // Defines an alias for the nlohmann::json library.
    using json = nlohmann::json;
    // Defines a structure for representing an updated block.
    struct CUpdatedBlock {
        SPHINXHash::SPHINX_256 hash;
        int height;
    };
    // Declares a static mutex for controlling access to block changes.
    static std::mutex cs_blockchange;
    // Declares a static condition variable for signaling block changes.
    static std::condition_variable cond_blockchange;
    // Declares a static variable for storing information about the latest block update.
    static CUpdatedBlock latestblock;

    // Calculate and return the difficulty for a given block.
    double GetDifficulty(const CBlockIndex* blockindex) {
        if (!blockindex) {
            return 0.0; // Handle invalid blockindex gracefully.
        }
        // Extract the shift value from the block's difficulty value.
        int nShift = (blockindex->nDifficultly >> 24) & 0xff;
        // Calculate the difficulty based on the block's difficulty value.
        double dDifficulty =
            static_cast<double>(0x0000ffff) / static_cast<double>(blockindex->nDifficultly & 0x00ffffff);
        // Increase the difficulty if the shift value is less than 29.
        while (nShift < 29) {
            dDifficulty *= 256.0;
            nShift++;
        }
        // Decrease the difficulty if the shift value is greater than 29.
        while (nShift > 29) {
            dDifficulty /= 256.0;
            nShift--;
        }
        // Return the calculated difficulty.
        return nDifficulty;
    }

    // Compute the next block and depth relative to the tip.
    static int ComputeNextBlockAndDepth(const CBlockIndex* tip, const CBlockIndex* blockindex, const CBlockIndex*& next) {
        // Find the block at the next height relative to the given block.
        next = tip->GetAncestor(blockindex->nHeight + 1);
        // Check if the next block exists and is a child of the given block.
        if (next && next->pprev == blockindex) {
            return tip->nHeight - blockindex->nHeight + 1; // Compute depth.
        }
        // The next block is not a child of the given block.
        next = nullptr;
        return (blockindex == tip) ? 1 : -1; // Handle cases where the block is the tip or not found.
    }

    // Parse a block's hash or height and return the corresponding block index.
    static const CBlockIndex* ParseHashOrHeight(const UniValue& param, ChainstateManager& chainman) {
        std::lock_guard<std::mutex> lock(cs_main);
        CChain& active_chain = chainman.ActiveChain();
        // Check if the parameter is a number (block height).
        if (param.isNum()) {
            // Extract the target block height from the parameter.
            const int height = param.getInt<int>();
            // Check if the target block height is negative.
            if (height < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Target block height is negative");
            }
            // Get the current tip of the active chain.
            const int current_tip = active_chain.Height();
            // Check if the target block height is after the current tip.
            if (height > current_tip) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Target block height is after the current tip");
            }
            // Return the block index corresponding to the target block height.
            return active_chain[height];
        } else {
            // Parse the parameter as a block hash.
            const SPHINXHash::SPHINX_256 hash = ParseHashV(param, "hash_or_height");
            // Look up the block index based on the hash.
            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
            // Check if the block index was not found.
            if (!pindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
            // Return the found block index.
            return pindex;
        }
    }


    //! Block header to json (using nlohmann::josn)
    // Serialize block header information to JSON.
    json blockheaderToJSON(const CBlockIndex* tip, const CBlockIndex* blockindex) {
        // Serialize passed information without accessing the chain state of the active chain.
        AssertLockNotHeld(cs_main); // For performance reasons

        json result;
        result["hash"] = blockindex->GetBlockHash().GetHex();
        const CBlockIndex* pnext;
        int confirmations = ComputeNextBlockAndDepth(tip, blockindex, pnext);
        result["confirmations"] = confirmations;
        result["height"] = blockindex->nHeight;
        result["version"] = blockindex->nVersion;
        result["versionHex"] = strprintf("%08x", blockindex->nVersion);
        result["merkleroot"] = blockindex->hashMerkleRoot.GetHex();
        result["time"] = static_cast<int64_t>(blockindex->nTime);
        result["mediantime"] = static_cast<int64_t>(blockindex->GetMedianTimePast());
        result["nonce"] = static_cast<uint64_t>(blockindex->nNonce);
        result["bits"] = strprintf("%08x", blockindex->nDifficultly);
        result["difficulty"] = GetDifficulty(blockindex);
        result["chainwork"] = blockindex->nChainWork.GetHex();
        result["nTx"] = static_cast<uint64_t>(blockindex->nTx);

        // Include previous and next block hashes if available.
        if (blockindex->pprev)
            result["previousblockhash"] = blockindex->pprev->GetBlockHash().GetHex();
        if (pnext)
            result["nextblockhash"] = pnext->GetBlockHash().GetHex();
        return result;
    }

    // Serialize a block to JSON.
    json blockToJSON(BlockManager& blockman, const CBlock& block, const CBlockIndex* tip, const CBlockIndex* blockindex, TxVerbosity verbosity) {
        json result = blockheaderToJSON(tip, blockindex);

        result["strippedsize"] = static_cast<int>(::GetSerializeSize(block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS));
        result["size"] = static_cast<int>(::GetSerializeSize(block, PROTOCOL_VERSION));
        result["weight"] = static_cast<int>(::GetBlockWeight(block));
        json txs;

        // Include transaction details based on verbosity level.
        switch (verbosity) {
            case TxVerbosity::SHOW_TXID:
                for (const CTransactionRef& tx : block.vtx) {
                    txs.push_back(tx->GetHash().GetHex());
                }
                break;
            case TxVerbosity::SHOW_DETAILS:
            case TxVerbosity::SHOW_DETAILS_AND_PREVOUT:
                CBlockUndo blockUndo;
                const bool is_not_pruned = WITH_LOCK(::cs_main, return !blockman.IsBlockPruned(blockindex));
                const bool have_undo = is_not_pruned && UndoReadFromDisk(blockUndo, blockindex);
                
                for (size_t i = 0; i < block.vtx.size(); ++i) {
                    const CTransactionRef& tx = block.vtx.at(i);
                    const CTxUndo* txundo = (have_undo && i > 0) ? &blockUndo.vtxundo.at(i - 1) : nullptr;
                    json objTx;
                    // Replace this placeholder with your own JSON serialization function for a transaction
                    objTx = {}; // Replace with actual transaction serialization.
                    txs.push_back(objTx);
                }
                break;
        }

        result["tx"] = txs;
        return result;
    }

    // Helper function to get the block count
    UniValue GetBlockCount(const JSONRPCRequest& request) {
        // Obtain the ChainstateManager for the current context.
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        // Acquire a lock on the main chain.
        LOCK(cs_main);
        // Return the height of the active chain (block count).
        return chainman.ActiveChain().Height();
    }

    // Helper function to get the best block hash
    UniValue GetBestBlockHash(const JSONRPCRequest& request) {
        // Obtain the ChainstateManager for the current context.
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        // Acquire a lock on the main chain.
        LOCK(cs_main);
        // Return the hash of the tip of the active chain (best block hash).
        return chainman.ActiveChain().Tip()->GetBlockHash().GetHex();
    }

    // Helper function to notify of a block change
    void NotifyBlockChange(const CBlockIndex* pindex) {
        // Check if a valid block index is provided.
        if (pindex) {
            // Acquire a lock for block change synchronization.
            LOCK(cs_blockchange);
            // Update the latest block information with the provided block index.
            latestblock.hash = pindex->GetBlockHash();
            latestblock.height = pindex->nHeight;
        }
        // Notify waiting threads about the block change.
        cond_blockchange.notify_all();
    }

    // Helper function to wait for a new block
    UniValue WaitForNewBlock(const JSONRPCRequest& request) {
        // Initialize a timeout variable.
        int timeout = 0;
        // Check if a timeout value is specified in the request.
        if (!request.params[0].isNull()) {
            timeout = request.params[0].getInt<int>();
        }
        // Initialize a block information structure.
        CUpdatedBlock block;
        {
            // Acquire a lock for block change synchronization.
            WAIT_LOCK(cs_blockchange, lock);
            // Store the current latest block information.
            block = latestblock;
            // Check if a timeout value is provided.
            if (timeout) {
                // Wait for a new block with a specified timeout.
                cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&block]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {
                    // Check if the block information has changed or if the RPC is no longer running.
                    return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning();
                });
            } else {
                // Wait indefinitely for a new block.
                cond_blockchange.wait(lock, [&block]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {
                    // Check if the block information has changed or if the RPC is no longer running.
                    return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning();
                });
            }
            // Update the block information after waiting.
            block = latestblock;
        }
        // Create and return a UniValue object with the new block information.
        UniValue ret(UniValue::VOBJ);
        ret.pushKV("hash", block.hash.GetHex());
        ret.pushKV("height", block.height);
        return ret;
    }


    // Define RPC methods
    RPCH GetBlockCountRPC() {
        return RPCH{
            "getblockcount",
            "Returns the height of the most-work fully-validated chain.\nThe genesis block has height 0.",
            {},
            RPCResult{RPCResult::Type::NUM, "", "The current block count"},
            RPCExamples{
                HelpExampleCli("getblockcount", "") + HelpExampleRpc("getblockcount", "")},
            GetBlockCount};
    }

    // Returns the hash of the best (tip) block in the most-work fully-validated chain.
    RPCH GetBestBlockHashRPC() {
        return RPCH{
            "getbestblockhash",
            "Returns the hash of the best (tip) block in the most-work fully-validated chain.",
            {},
            RPCResult{RPCResult::Type::STR_HEX, "", "the block hash, hex-encoded"},
            RPCExamples{
                HelpExampleCli("getbestblockhash", "") + HelpExampleRpc("getbestblockhash", "")
            },
            GetBestBlockHash
        };
    }

    // Waits for a specific new block and returns useful info about it. Returns the current block on timeout or exit.
    RPCH WaitForNewBlockRPC() {
        return RPCH{
            "waitfornewblock",
            "Waits for a specific new block and returns useful info about it. Returns the current block on timeout or exit.",
            {{"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."}},
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                    {RPCResult::Type::NUM, "height", "Block height"},
                }
            },
            RPCExamples{
                HelpExampleCli("waitfornewblock", "1000") + HelpExampleRpc("waitfornewblock", "1000")
            },
            WaitForNewBlock
        };
    }

    // Helper function to wait for a specific block hash
    UniValue WaitForBlock(const JSONRPCRequest& request) {
        // Initialize a timeout variable.
        int timeout = 0;
        // Parse the block hash parameter from the request.
        SPHINXHash::SPHINX_256 hash(ParseHashV(request.params[0], "blockhash"));
        // Check if a timeout value is specified in the request.
        if (!request.params[1].isNull()) {
            // Set the timeout value from the request.
            timeout = request.params[1].getInt<int>();
        }
        // Initialize a block information structure.
        CUpdatedBlock block;
        {
            // Acquire a lock for block change synchronization.
            WAIT_LOCK(cs_blockchange, lock);
            // Check if a timeout value is provided.
            if (timeout) {
                // Wait for a new block with the specified hash and timeout.
                cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&hash]() 
                EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {
                    // Check if the latest block hash matches the specified hash or if the RPC is no longer running.
                    return latestblock.hash == hash || !IsRPCRunning();
                });
            } else {
                // Wait indefinitely for a new block with the specified hash.
                cond_blockchange.wait(lock, [&hash]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {
                    // Check if the latest block hash matches the specified hash or if the RPC is no longer running.
                    return latestblock.hash == hash || !IsRPCRunning();
                });
            }
            // Update the block information after waiting.
            block = latestblock;
        }
        // Create and return a UniValue object with the new block information.
        UniValue ret(UniValue::VOBJ);
        ret.pushKV("hash", block.hash.GetHex());
        ret.pushKV("height", block.height);
        return ret;
    }

    // Helper function to wait for a specific block height
    UniValue WaitForBlockHeight(const JSONRPCRequest& request) {
        // Initialize a timeout variable.
        int timeout = 0;
        // Parse the target block height from the request.
        int height = request.params[0].getInt<int>();
        // Check if a timeout value is specified in the request.
        if (!request.params[1].isNull()) {
            // Set the timeout value from the request.
            timeout = request.params[1].getInt<int>();
        }
        // Initialize a block information structure.
        CUpdatedBlock block;
        {
            // Acquire a lock for block change synchronization.
            WAIT_LOCK(cs_blockchange, lock);
            // Check if a timeout value is provided.
            if (timeout) {
                // Wait for a block with a height greater than or equal to the specified height and with a timeout.
                cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&height]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {
                    // Check if the latest block height is greater than or equal to the target height or if the RPC is no longer running.
                    return latestblock.height >= height || !IsRPCRunning();
                });
            } else {
                // Wait indefinitely for a block with a height greater than or equal to the specified height.
                cond_blockchange.wait(lock, [&height]() EXCLUSIVE_LOCKS_REQUIRED(cs_blockchange) {
                    // Check if the latest block height is greater than or equal to the target height or if the RPC is no longer running.
                    return latestblock.height >= height || !IsRPCRunning();
                });
            }
            // Update the block information after waiting.
            block = latestblock;
        }
        // Create and return a UniValue object with the new block information.
        UniValue ret(UniValue::VOBJ);
        ret.pushKV("hash", block.hash.GetHex());
        ret.pushKV("height", block.height);
        return ret;
    }

    // Define RPC methods
    RPCH WaitForBlockRPC() {
        return RPCH{
            "waitforblock",
            "Waits for a specific new block and returns useful info about it.\nReturns the current block on timeout or exit.",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash to wait for."},
                {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                    {RPCResult::Type::NUM, "height", "Block height"},
                }},
            RPCExamples{
                HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\" 1000") + 
                HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")},
            WaitForBlock};
    }

    // Waits for (at least) block height and returns the height and hash of the current tip. Returns the current block on timeout or exit.
    RPCH WaitForBlockHeightRPC() {
        return RPCH{
            "waitforblockheight",
            "Waits for (at least) block height and returns the height and hash of the current tip. Returns the current block on timeout or exit.",
            {
                {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height to wait for."},
                {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                    {RPCResult::Type::NUM, "height", "Block height"},
                }
            },
            RPCExamples{
                HelpExampleCli("waitforblockheight", "100 1000") +
                HelpExampleRpc("waitforblockheight", "100, 1000")
            },
            WaitForBlockHeight
        };
    }

    // Define RPC method to sync with the validation interface queue
    RPCH SyncWithValidationInterfaceQueueRPC() {
        return RPCH{
            "syncwithvalidationinterfacequeue",
            "Waits for the validation interface queue to catch up on everything that was there when we entered this function.",
            {},
            RPCResult{RPCResult::Type::NONE, "", ""},
            RPCExamples{
                HelpExampleCli("syncwithvalidationinterfacequeue", "") + 
                HelpExampleRpc("syncwithvalidationinterfacequeue", "")},
            [](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                SyncWithValidationInterfaceQueue();
                return UniValue::VNULL;
            },
        };
    }

    // Define RPC method to get the current difficulty
    RPCH GetDifficultyRPC() {
        return RPCH{
            "getdifficulty",
            "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.",
            {},
            RPCResult{
                RPCResult::Type::NUM, "", "the proof-of-work difficulty as a multiple of the minimum difficulty."},
            RPCExamples{
                HelpExampleCli("getdifficulty", "") + 
                HelpExampleRpc("getdifficulty", "")},
            [](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                return GetDifficulty(chainman.ActiveChain().Tip());
            },
        };
    }

    // Helper function to fetch a block from a peer
    UniValue GetBlockFromPeer(const JSONRPCRequest& request) {
        // Obtain the NodeContext for the current context.
        const NodeContext& node = EnsureAnyNodeContext(request.context);
        // Obtain the ChainstateManager associated with the node.
        ChainstateManager& chainman = EnsureChainman(node);
        // Obtain the PeerManager associated with the node.
        PeerManager& peerman = EnsurePeerman(node);
        // Parse the block hash parameter from the request.
        const SPHINXHash::SPHINX_256& block_hash = ParseHashV(request.params[0], "blockhash");
        // Parse the peer ID from the request.
        const NodeId peer_id = request.params[1].getInt<int64_t>();
        // Lookup the block index for the specified block hash.
        const CBlockIndex* const index = WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block_hash););
        // Check if the block index exists.
        if (!index) {
            throw JSONRPCError(RPC_MISC_ERROR, "Block header missing");
        }

        // Fetching blocks before the node has synced past their height can prevent block files from
        // being pruned, so we avoid it if the node is in prune mode.
        if (chainman.m_blockman.IsPruneMode() && index->nHeight > WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()->nHeight)) {
            throw JSONRPCError(RPC_MISC_ERROR, "In prune mode, only blocks that the node has already synced previously can be fetched from a peer");
        }
        // Check if the block already has data.
        const bool block_has_data = WITH_LOCK(::cs_main, return index->nStatus & BLOCK_HAVE_DATA);
        if (block_has_data) {
            throw JSONRPCError(RPC_MISC_ERROR, "Block already downloaded");
        }
        // Fetch the block from the specified peer.
        if (const auto err = peerman.FetchBlock(peer_id, *index)) {
            throw JSONRPCError(RPC_MISC_ERROR, err.value());
        }
        // Return an empty UniValue object.
        return UniValue::VOBJ;
    }

    // Helper function to get the block hash at a specific height
    UniValue GetBlockHash(const JSONRPCRequest& request) {
        // Obtain the ChainstateManager associated with the request's context.
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        // Acquire a lock to ensure thread safety.
        LOCK(cs_main);
        // Obtain a reference to the active chain.
        const CChain& active_chain = chainman.ActiveChain();
        // Retrieve the block height from the request parameters.
        int nHeight = request.params[0].getInt<int>();
        // Check if the specified block height is out of range.
        if (nHeight < 0 || nHeight > active_chain.Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");
        }
        // Retrieve the block index at the specified height.
        const CBlockIndex* pblockindex = active_chain[nHeight];
        // Return the block hash as a hexadecimal string.
        return pblockindex->GetBlockHash().GetHex();
    }

    // Define RPC methods
    RPCH GetBlockFromPeerRPC() {
        return RPCH{
            "getblockfrompeer",
            "Attempt to fetch block from a given peer.\n\n"
            "We must have the header for this block, e.g. using submitheader.\n"
            "Subsequent calls for the same block and a new peer will cause the response from the previous peer to be ignored.\n"
            "Peers generally ignore requests for a stale block that they never fully verified, or one that is more than a month old.\n"
            "When a peer does not respond with a block, we will disconnect.\n"
            "Note: The block could be re-pruned as soon as it is received.\n\n"
            "Returns an empty JSON object if the request was successfully scheduled.",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash to try to fetch"},
                {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to fetch it from (see getpeerinfo for peer IDs)"},
            },
            RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "", {}},
            RPCExamples{
                HelpExampleCli("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
                + HelpExampleRpc("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")},
            GetBlockFromPeer};
    }

    // Returns hash of block in best-block-chain at height provided.
    RPCH GetBlockHashRPC() {
        return RPCH{
            "getblockhash",
            "Returns hash of block in best-block-chain at height provided.",
            {
                {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The height index"},
            },
            RPCResult{
                RPCResult::Type::STR_HEX, "", "The block hash"
            },
            RPCExamples{
                HelpExampleCli("getblockhash", "1000")
                + HelpExampleRpc("getblockhash", "1000")
            },
            GetBlockHash
        };
    }

    // Helper function to get the block header in JSON format
    json GetBlockHeaderJSON(const CBlockIndex* tip, const CBlockIndex* pblockindex) {
        json headerJSON;
        headerJSON["hash"] = pblockindex->GetBlockHash().GetHex();
        headerJSON["confirmations"] = tip->GetBlockCount() - pblockindex->GetBlockCount() + 1;
        headerJSON["height"] = pblockindex->nHeight;
        headerJSON["version"] = pblockindex->nVersion;
        headerJSON["versionHex"] = HexStr(pblockindex->nVersion);
        headerJSON["merkleroot"] = pblockindex->hashMerkleRoot.GetHex();
        headerJSON["time"] = pblockindex->nTime;
        headerJSON["mediantime"] = tip->GetMedianTimePast();
        headerJSON["nonce"] = pblockindex->nNonce;
        headerJSON["bits"] = strprintf("%08x", pblockindex->nBits);
        headerJSON["difficulty"] = GetDifficulty(pblockindex);
        headerJSON["chainwork"] = pblockindex->nChainWork.GetHex();
        headerJSON["nTx"] = static_cast<int>(pblockindex->nChainTx);
        if (pblockindex->pprev) {
            headerJSON["previousblockhash"] = pblockindex->pprev->GetBlockHash().GetHex();
        }
        if (pblockindex->pnext) {
            headerJSON["nextblockhash"] = pblockindex->pnext->GetBlockHash().GetHex();
        }
        // Assuming blockheaderToJSON is defined and returns additional JSON data
        json additionalData = blockheaderToJSON(tip, pblockindex);
        headerJSON.merge_patch(additionalData); // Merge additional data into headerJSON
        return headerJSON;
    }

    // Helper function to get the block header in serialized, hex-encoded format
    std::string GetBlockHeaderHex(const CBlockIndex* pblockindex) {
        DataStream ssBlock{};
        ssBlock << pblockindex->GetBlockHeader();
        return HexStr(ssBlock);
    }

    // Define RPC method for getting block header information
    RPCH GetBlockHeaderRPC() {
        return RPCH{
            "getblockheader",
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
            "If verbose is true, returns an Object with information about blockheader <hash>.\n",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                {"verbose", RPCArg::Type::BOOL, RPCArg::Default{true}, "true for a JSON object, false for the hex-encoded data"},
            },
            {
                RPCResult{"for verbose = true",
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                        {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                        {RPCResult::Type::NUM, "height", "The block height or index"},
                        {RPCResult::Type::NUM, "version", "The block version"},
                        {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                        {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                        {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM, "nonce", "The nonce"},
                        {RPCResult::Type::STR_HEX, "bits", "The bits"},
                        {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                        {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the current chain"},
                        {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                        {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                        {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                    }},
                RPCResult{"for verbose=false",
                    RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
            },
            RPCExamples{
                HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                + HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")},
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue
            {
                // Parse the block hash from the request parameters.
                const SPHINXHash::SPHINX_256& hash = ParseHashV(request.params[0], "hash");
                bool fVerbose = true;
                // Check if the 'verbose' parameter is provided and set it accordingly.
                if (!request.params[1].isNull()) {
                    fVerbose = request.params[1].get_bool();
                }
                // Initialize block index and tip variables.
                const CBlockIndex* pblockindex;
                const CBlockIndex* tip;
                {
                    // Obtain the ChainstateManager associated with the request's context.
                    ChainstateManager& chainman = EnsureAnyChainman(request.context);
                    LOCK(cs_main);
                    // Lookup the block index for the provided hash.
                    pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
                    tip = chainman.ActiveChain().Tip();
                }
                // Check if the block index exists, otherwise, throw an error.
                if (!pblockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
                // If 'verbose' is false, return the hex-encoded block header data.
                if (!fVerbose) {
                    return GetBlockHeaderHex(pblockindex);
                }
                // If 'verbose' is true, return the JSON object with block header information.
                return GetBlockHeaderJSON(tip, pblockindex);
            },
        };
    }


    // Retrieve and validate a block from disk.
    static CBlock GetBlockChecked(BlockManager& blockman, const CBlockIndex* pblockindex)
    {
        CBlock block;
        {
            LOCK(cs_main);
            if (blockman.IsBlockPruned(pblockindex)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Block not available (pruned data)");
            }
        }

        if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
            // Block not found on disk. This could be because we have the block
            // header in our index but not yet have the block or did not accept the
            // block. Or if the block was pruned right after we released the lock above.
            throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
        }

        return block;
    }

    // Retrieve and validate undo data for a block from disk.
    static CBlockUndo GetUndoChecked(BlockManager& blockman, const CBlockIndex* pblockindex)
    {
        CBlockUndo blockUndo;

        // The Genesis block does not have undo data
        if (pblockindex->nHeight == 0) return blockUndo;

        {
            LOCK(cs_main);
            if (blockman.IsBlockPruned(pblockindex)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Undo data not available (pruned data)");
            }
        }

        if (!UndoReadFromDisk(blockUndo, pblockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Can't read undo data from disk");
        }

        return blockUndo;
    }

    // Define the result format for the 'getblock' command's 'vin' field.
    const RPCResult GetBlockVinResultFormat{
        RPCResult::Type::ARR, "vin", "",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ELISION, "", "The same output as verbosity = 2"},
                {RPCResult::Type::OBJ, "prevout", "(Only if undo information is available)",
                {
                    {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                    {RPCResult::Type::NUM, "height", "The height of the prevout"},
                    {RPCResult::Type::STR_ASSET, "value", "The value in " + CURRENCY_UNIT},
                    {RPCResult::Type::OBJ, "scriptPubKey", "",
                    {
                        {RPCResult::Type::STR, "asm", "Disassembly of the public key script"},
                        {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                        {RPCResult::Type::STR_HEX, "hex", "The raw public key script bytes, hex-encoded"},
                        {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                        {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
                    }},
                }},
            }},
        }
    };

    // Serialize a block to its hexadecimal representation.
    UniValue SerializeBlockToHex(const CBlock& block) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
        ssBlock << block;
        return HexStr(ssBlock);
    }

    // Serialize a block to a JSON format with specified verbosity.
    nlohmann::json SerializeBlockToJSON(const CBlock& block, const CBlockIndex* pblockindex, int verbosity) {
        nlohmann::json blockInfo;

        blockInfo["hash"] = pblockindex->GetBlockHash().GetHex();
        blockInfo["confirmations"] = pblockindex->GetConfirmations();
        blockInfo["size"] = block.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION);
        blockInfo["strippedsize"] = block.GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
        blockInfo["weight"] = pblockindex->nBlockWeight;
        blockInfo["height"] = pblockindex->nHeight;
        blockInfo["version"] = pblockindex->nVersion;
        blockInfo["versionHex"] = HexStr(pblockindex->nVersion);
        blockInfo["merkleroot"] = block.hashMerkleRoot.GetHex();
        blockInfo["tx"] = pblockindex->GetTxHashes();
        blockInfo["time"] = pblockindex->GetBlockTime();
        blockInfo["mediantime"] = pblockindex->GetMedianTimePast();
        blockInfo["nonce"] = pblockindex->nNonce;
        blockInfo["bits"] = strprintf("%08x", pblockindex->nBits);
        blockInfo["difficulty"] = GetDifficulty(pblockindex);
        blockInfo["chainwork"] = pblockindex->nChainWork.GetHex();
        blockInfo["nTx"] = pblockindex->nChainTx;
        if (pblockindex->pprev) {
            blockInfo["previousblockhash"] = pblockindex->pprev->GetBlockHash().GetHex();
        }
        if (pblockindex->pnext) {
            blockInfo["nextblockhash"] = pblockindex->pnext->GetBlockHash().GetHex();
        }

        if (verbosity >= 2) {
            nlohmann::json txArray;

            for (const CTransaction& tx : block.vtx) {
                nlohmann::json txInfo = SerializeTransactionToJSON(tx, verbosity);
                txArray.push_back(txInfo);
            }

            blockInfo["tx"] = txArray;

            if (verbosity >= 3) {
                // Include prevout information for inputs (only for unpruned blocks)
                // Implement as needed based on your requirements
            }
        }

        return blockInfo;
    }

    // Define RPC method for getting block information
    RPCH GetBlockRPC() {
        return RPCH{
            "getblock",
            "\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbosity is 1, returns an Object with information about block <hash>.\n"
            "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.\n"
            "If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including prevout information for inputs (only for unpruned blocks in the current best chain).\n",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{1}, "0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data, and 3 for JSON object with transaction data including prevout information for inputs",
                RPCArgOptions{.skip_type_check = true}},
            },
            {
                RPCResult{"for verbosity = 0",
                    RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                RPCResult{"for verbosity >= 1",
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                        {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                        {RPCResult::Type::NUM, "size", "The block size"},
                        {RPCResult::Type::NUM, "strippedsize", "The block size excluding witness data"},
                        {RPCResult::Type::NUM, "weight", "The block weight as defined in SIP 141"},
                        {RPCResult::Type::NUM, "height", "The block height or index"},
                        {RPCResult::Type::NUM, "version", "The block version"},
                        {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                        {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                        {RPCResult::Type::ARR, "tx", "The transaction ids",
                            {{RPCResult::Type::STR_HEX, "", "The transaction id"}}},
                        {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM, "nonce", "The nonce"},
                        {RPCResult::Type::STR_HEX, "bits", "The bits"},
                        {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                        {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the chain up to this block (in hex)"},
                        {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                        {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                        {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                    }},
            },
            RPCExamples{
                HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")},
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue
            {
                // Parse the block hash from the request parameters.
                SPHINXHash::SPHINX_256 hash(ParseHashV(request.params[0], "blockhash"));
                // Get the verbosity level from the request parameters.
                int verbosity = request.params[1].get_int(1);
                // Initialize block index and tip variables.
                const CBlockIndex* pblockindex;
                const CBlockIndex* tip;
                // Obtain the ChainstateManager associated with the request's context.
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                {
                    LOCK(cs_main);
                    // Lookup the block index for the provided hash.
                    pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
                    tip = chainman.ActiveChain().Tip();
                    // Check if the block index exists, otherwise, throw an error.
                    if (!pblockindex) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                    }
                }
                // Get the block data for the specified block index.
                const CBlock block{GetBlockChecked(chainman.m_blockman, pblockindex)};
                // Depending on verbosity, return different block information.
                if (verbosity <= 0) {
                    return GetBlockHex(block);
                } else {
                    return GetBlockJSON(block, pblockindex, verbosity);
                }
            },
        };
    }

    // Prunes the blockchain up to the specified block height or timestamp.
    UniValue PruneBlockchain(const JSONRPCRequest& request) {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        
        // Checks if the node is in prune mode; if not, throws an error.
        if (!chainman.m_blockman.IsPruneMode()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Cannot prune blocks because the node is not in prune mode.");
        }

        // Acquires a lock on the main chain.
        LOCK(cs_main);
        Chainstate& active_chainstate = chainman.ActiveChainstate();
        CChain& active_chain = active_chainstate.m_chain;

        // Retrieves the requested block height or timestamp parameter.
        int heightParam = request.params[0].getInt<int>();
        
        // Validates that the block height is not negative; if it is, throws an error.
        if (heightParam < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative block height.");
        }

        // If the height parameter is a timestamp, converts it to a block height.
        if (heightParam > 1000000000) {
            const CBlockIndex* pindex = active_chain.FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW, 0);
            if (!pindex) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not find a block with at least the specified timestamp.");
            }
            heightParam = pindex->nHeight;
        }

        // Converts heightParam to an unsigned integer.
        unsigned int height = static_cast<unsigned int>(heightParam);
        unsigned int chainHeight = static_cast<unsigned int>(active_chain.Height());
        
        // Checks if pruning is possible and sets the target height.
        if (chainHeight < chainman.GetParams().PruneAfterHeight()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Blockchain is too short for pruning.");
        } else if (height > chainHeight) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain is shorter than the attempted prune height.");
        } else if (height > chainHeight - MIN_BLOCKS_TO_KEEP) {
            LogPrint(BCLog::RPC, "Attempt to prune blocks close to the tip. Retaining the minimum number of blocks.\n");
            height = chainHeight - MIN_BLOCKS_TO_KEEP;
        }

        // Prunes the block files up to the specified height and returns the new height.
        PruneBlockFilesManual(active_chainstate, height);
        const CBlockIndex& block = *CHECK_NONFATAL(active_chain.Tip());
        const CBlockIndex* last_block = active_chainstate.m_blockman.GetFirstStoredBlock(block);

        // Returns the new height after pruning.
        return static_cast<int64_t>(last_block->nHeight - 1);
    }

    // Function
    RPCH PruneBlockchainRPC() {
        return RPCH{
            "pruneblockchain", "",
            {
                {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block height to prune up to. May be set to a discrete height, or to a " + UNIX_EPOCH_TIME + "\n"
                "                  to prune blocks whose block time is at least 2 hours older than the provided timestamp."},
            },
            {
                RPCResult{RPCResult::Type::NUM, "", "Height of the last block pruned"},
            },
            RPCExamples{
                HelpExampleCli("pruneblockchain", "1000")
            + HelpExampleRpc("pruneblockchain", "1000")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                return PruneBlockchain(request);
            },
        };
    }

    // Parse the hash type input and convert it to a CoinStatsHashType enum.
    CoinStatsHashType ParseHashType(const std::string& hash_type_input) {
        if (hash_type_input == "hash_serialized_2") {
            return CoinStatsHashType::HASH_SERIALIZED;
        } else if (hash_type_input == "muhash") {
            return CoinStatsHashType::MUHASH;
        } else if (hash_type_input == "none") {
            return CoinStatsHashType::NONE;
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("'%s' is not a valid hash_type", hash_type_input));
        }
    }

    // Calculate UTXO statistics based on the specified hash_type.
    std::optional<kernel::CCoinsStats> CalculateUTXOStats(CCoinsView* view, node::BlockManager& blockman,
                                                        kernel::CoinStatsHashType hash_type,
                                                        const std::function<void()>& interruption_point = {},
                                                        const CBlockIndex* pindex = nullptr,
                                                        bool index_requested = true)
    {
        // Check if a specific hash type is selected and if an index is available.
        if ((hash_type == kernel::CoinStatsHashType::MUHASH || hash_type == kernel::CoinStatsHashType::NONE) && g_coin_stats_index && index_requested) {
            // Check if a specific block index is provided or use the best block if not.
            if (pindex) {
                return g_coin_stats_index->LookUpStats(*pindex);
            } else {
                LOCK(cs_main);
                CBlockIndex& block_index = *CHECK_NONFATAL(WITH_LOCK(::cs_main, return blockman.LookupBlockIndex(view->GetBestBlock())));
                return g_coin_stats_index->LookUpStats(block_index);
            }
        }
        // Ensure that the provided block index matches the best block.
        CHECK_NONFATAL(!pindex || pindex->GetBlockHash() == view->GetBestBlock());
        // Compute UTXO statistics based on the selected hash type.
        return kernel::ComputeUTXOStats(hash_type, view, blockman, interruption_point);
    }

    // Function
    RPCH GetTxOutSetInfoRPC() {
        return RPCH{
            "gettxoutsetinfo",
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time if you are not using coinstatsindex.\n",
            {
                {"hash_type", RPCArg::Type::STR, RPCArg::Default{"hash_serialized_2"}, "Which UTXO set hash should be calculated. Options: 'hash_serialized_2' (the legacy algorithm), 'muhash', 'none'."},
                {"hash_or_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"the current best block"}, "The block hash or height of the target height (only available with coinstatsindex).",
                RPCArgOptions{
                    .skip_type_check = true,
                    .type_str = {"", "string or numeric"},
                }},
                {"use_index", RPCArg::Type::BOOL, RPCArg::Default{true}, "Use coinstatsindex, if available."},
            },
            {
                RPCResult{RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "height", "The block height (index) of the returned statistics"},
                    {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at which these statistics are calculated"},
                    {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs"},
                    {RPCResult::Type::NUM, "bogosize", "Database-independent, meaningless metric indicating the UTXO set size"},
                    {RPCResult::Type::STR_HEX, "hash_serialized_2", /*optional=*/true, "The serialized hash (only present if 'hash_serialized_2' hash_type is chosen)"},
                    {RPCResult::Type::STR_HEX, "muhash", /*optional=*/true, "The serialized hash (only present if 'muhash' hash_type is chosen)"},
                    {RPCResult::Type::NUM, "transactions", /*optional=*/true, "The number of transactions with unspent outputs (not available when coinstatsindex is used)"},
                    {RPCResult::Type::NUM, "disk_size", /*optional=*/true, "The estimated size of the chainstate on disk (not available when coinstatsindex is used)"},
                    {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of coins in the UTXO set"},
                    {RPCResult::Type::STR_AMOUNT, "total_unspendable_amount", /*optional=*/true, "The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)"},
                    {RPCResult::Type::OBJ, "block_info", /*optional=*/true, "Info on amounts in the block at this block height (only available if coinstatsindex is used)",
                    {
                        {RPCResult::Type::STR_AMOUNT, "prevout_spent", "Total amount of all prevouts spent in this block"},
                        {RPCResult::Type::STR_AMOUNT, "coinbase", "Coinbase subsidy amount of this block"},
                        {RPCResult::Type::STR_AMOUNT, "new_outputs_ex_coinbase", "Total amount of new outputs created by this block"},
                        {RPCResult::Type::STR_AMOUNT, "unspendable", "Total amount of unspendable outputs created in this block"},
                        {RPCResult::Type::OBJ, "unspendables", "Detailed view of the unspendable categories",
                        {
                            {RPCResult::Type::STR_AMOUNT, "genesis_block", "The unspendable amount of the Genesis block subsidy"},
                            {RPCResult::Type::STR_AMOUNT, "sip30", "Transactions overridden by duplicates (no longer possible with SIP30)"},
                            {RPCResult::Type::STR_AMOUNT, "scripts", "Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)"},
                            {RPCResult::Type::STR_AMOUNT, "unclaimed_rewards", "Fee rewards that miners did not claim in their coinbase transaction"},
                        }}
                    }},
                }},
            },
            RPCExamples{
                HelpExampleCli("gettxoutsetinfo", "") +
                HelpExampleCli("gettxoutsetinfo", R"("none")") +
                HelpExampleCli("gettxoutsetinfo", R"("none" 1000)") +
                HelpExampleCli("gettxoutsetinfo", R"("none" '"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"')") +
                HelpExampleCli("-named gettxoutsetinfo", R"(hash_type='muhash' use_index='false')") +
                HelpExampleRpc("gettxoutsetinfo", "") +
                HelpExampleRpc("gettxoutsetinfo", R"("none")") +
                HelpExampleRpc("gettxoutsetinfo", R"("none", 1000)") +
                HelpExampleRpc("gettxoutsetinfo", R"("none", "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09")")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue
            {
                UniValue ret(UniValue::VOBJ);

                const CBlockIndex* pindex{nullptr};
                const CoinStatsHashType hash_type{request.params[0].isNull() ? CoinStatsHashType::HASH_SERIALIZED : ParseHashType(request.params[0].get_str())};
                bool index_requested = request.params[2].isNull() || request.params[2].get_bool();

                NodeContext& node = EnsureAnyNodeContext(request.context);
                ChainstateManager& chainman = EnsureChainman(node);
                Chainstate& active_chainstate = chainman.ActiveChainstate();
                active_chainstate.ForceFlushStateToDisk();

                CCoinsView* coins_view;
                BlockManager* blockman;
                {
                    LOCK(cs_main);
                    coins_view = &active_chainstate.CoinsDB();
                    blockman = &active_chainstate.m_blockman;
                    pindex = blockman->LookupBlockIndex(coins_view->GetBestBlock());
                }

                if (!request.params[1].isNull()) {
                    if (!g_coin_stats_index) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Querying specific block heights requires coinstatsindex");
                    }

                    if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "hash_serialized_2 hash type cannot be queried for a specific block");
                    }

                    if (!index_requested) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot set use_index to false when querying for a specific block");
                    }
                    pindex = ParseHashOrHeight(request.params[1], chainman);
                }

                if (index_requested && g_coin_stats_index) {
                    if (!g_coin_stats_index->BlockUntilSyncedToCurrentChain()) {
                        const IndexSummary summary{g_coin_stats_index->GetSummary()};

                        if (pindex->nHeight > summary.best_block_height) {
                            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to get data because coinstatsindex is still syncing. Current height: %d", summary.best_block_height));
                        }
                    }
                }

                const std::optional<CCoinsStats> maybe_stats = CalculateUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex, index_requested);
                if (maybe_stats.has_value()) {
                    const CCoinsStats& stats = maybe_stats.value();
                    ret.pushKV("height", (int64_t)stats.nHeight);
                    ret.pushKV("bestblock", stats.hashBlock.GetHex());
                    ret.pushKV("txouts", (int64_t)stats.nTransactionOutputs);
                    ret.pushKV("bogosize", (int64_t)stats.nBogoSize);
                    if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
                        ret.pushKV("hash_serialized_2", stats.hashSerialized.GetHex());
                    }
                    if (hash_type == CoinStatsHashType::MUHASH) {
                        ret.pushKV("muhash", stats.hashSerialized.GetHex());
                    }
                    CHECK_NONFATAL(stats.total_amount.has_value());
                    ret.pushKV("total_amount", ValueFromAmount(stats.total_amount.value()));
                    if (!stats.index_used) {
                        ret.pushKV("transactions", static_cast<int64_t>(stats.nTransactions));
                        ret.pushKV("disk_size", stats.nDiskSize);
                    } else {
                        ret.pushKV("total_unspendable_amount", ValueFromAmount(stats.total_unspendable_amount));

                        CCoinsStats prev_stats{};
                        if (pindex->nHeight > 0) {
                            const std::optional<CCoinsStats> maybe_prev_stats = CalculateUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex->pprev, index_requested);
                            if (!maybe_prev_stats) {
                                throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
                            }
                            prev_stats = maybe_prev_stats.value();
                        }

                        UniValue block_info(UniValue::VOBJ);
                        block_info.pushKV("prevout_spent", ValueFromAmount(stats.total_prevout_spent_amount - prev_stats.total_prevout_spent_amount));
                        block_info.pushKV("coinbase", ValueFromAmount(stats.total_coinbase_amount - prev_stats.total_coinbase_amount));
                        block_info.pushKV("new_outputs_ex_coinbase", ValueFromAmount(stats.total_new_outputs_ex_coinbase_amount - prev_stats.total_new_outputs_ex_coinbase_amount));
                        block_info.pushKV("unspendable", ValueFromAmount(stats.total_unspendable_amount - prev_stats.total_unspendable_amount));

                        UniValue unspendables(UniValue::VOBJ);
                        unspendables.pushKV("genesis_block", ValueFromAmount(stats.total_unspendables_genesis_block - prev_stats.total_unspendables_genesis_block));
                        unspendables.pushKV("sip30", ValueFromAmount(stats.total_unspendables_sip30 - prev_stats.total_unspendables_sip30));
                        unspendables.pushKV("scripts", ValueFromAmount(stats.total_unspendables_scripts - prev_stats.total_unspendables_scripts));
                        unspendables.pushKV("unclaimed_rewards", ValueFromAmount(stats.total_unspendables_unclaimed_rewards - prev_stats.total_unspendables_unclaimed_rewards));
                        block_info.pushKV("unspendables", unspendables);

                        ret.pushKV("block_info", block_info);
                    }
                } else {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
                }
                return ret;
            },
        };
    }

    // Define an RPC method to get details about an unspent transaction output.
    RPCH GetTxOutRPC() {
        return RPCH{
            "gettxout",
            "\nReturns details about an unspent transaction output.\n",
            {
                {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
                {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "vout number"},
                {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include the mempool. Note that an unspent output that is spent in the mempool won't appear."},
            },
            {
                RPCResult{"If the UTXO was not found", RPCResult::Type::NONE, "", ""},
                RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                    {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                    {RPCResult::Type::STR_AMOUNT, "value", "The transaction value in " + CURRENCY_UNIT},
                    {RPCResult::Type::OBJ, "scriptPubKey", "", {
                        {RPCResult::Type::STR, "asm", "Disassembly of the public key script"},
                        {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                        {RPCResult::Type::STR_HEX, "hex", "The raw public key script bytes, hex-encoded"},
                        {RPCResult::Type::STR, "type", "The type, e.g., pubkeyhash"},
                        {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                    }},
                    {RPCResult::Type::BOOL, "coinbase", "Coinbase or not"},
                }},
            },
            RPCExamples{
                "\nGet unspent transactions\n"
                + HelpExampleCli("listunspent", "") +
                "\nView the details\n"
                + HelpExampleCli("gettxout", "\"txid\" 1") +
                "\nAs a JSON-RPC call\n"
                + HelpExampleRpc("gettxout", "\"txid\", 1")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                // Get necessary context and manager instances.
                NodeContext& node = EnsureAnyNodeContext(request.context);
                ChainstateManager& chainman = EnsureChainman(node);
                LOCK(cs_main);
                UniValue ret(UniValue::VOBJ);

                // Parse input parameters.
                SPHINXHash::SPHINX_256 hash(ParseHashV(request.params[0], "txid"));
                COutPoint out{hash, request.params[1].getInt<uint32_t>()};
                bool fMempool = true;
                if (!request.params[2].isNull()) {
                    fMempool = request.params[2].get_bool();
                }

                // Initialize coin and view based on mempool inclusion.
                Coin coin;
                Chainstate& active_chainstate = chainman.ActiveChainstate();
                CCoinsViewCache* coins_view = &active_chainstate.CoinsTip();

                if (fMempool) {
                    const CTxMemPool& mempool = EnsureMemPool(node);
                    LOCK(mempool.cs);
                    CCoinsViewMemPool view(coins_view, mempool);
                    if (!view.GetCoin(out, coin) || mempool.isSpent(out)) {
                        return UniValue::VNULL;
                    }
                } else {
                    if (!coins_view->GetCoin(out, coin)) {
                        return UniValue::VNULL;
                    }
                }

                // Calculate confirmations and add details to the result.
                const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(coins_view->GetBestBlock());
                ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
                if (coin.nHeight == MEMPOOL_HEIGHT) {
                    ret.pushKV("confirmations", 0);
                } else {
                    ret.pushKV("confirmations", (int64_t)(pindex->nHeight - coin.nHeight + 1));
                }
                ret.pushKV("value", ValueFromAmount(coin.out.nValue));
                UniValue o(UniValue::VOBJ);
                ScriptToUniv(coin.out.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
                ret.pushKV("scriptPubKey", o);
                ret.pushKV("coinbase", (bool)coin.fCoinBase);

                return ret;
            },
        };
    }

    // Define an RPC method to verify the blockchain database.
    RPCH VerifyChainRPC() {
        return RPCH{
            "verifychain",
            "\nVerifies blockchain database.\n",
            {
                {"checklevel", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, range=0-4", DEFAULT_CHECKLEVEL)},
                    strprintf("How thorough the block verification is:\n%s", MakeUnorderedList(CHECKLEVEL_DOC))},
                {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, 0=all", DEFAULT_CHECKBLOCKS)}, "The number of blocks to check."},
            },
            RPCResult{
                RPCResult::Type::BOOL, "", "Verification finished successfully. If false, check debug.log for reason."},
            RPCExamples{
                HelpExampleCli("verifychain", "")
                + HelpExampleRpc("verifychain", "")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                const int check_level{request.params[0].isNull() ? DEFAULT_CHECKLEVEL : request.params[0].getInt<int>()};
                const int check_depth{request.params[1].isNull() ? DEFAULT_CHECKBLOCKS : request.params[1].getInt<int>()};
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                Chainstate& active_chainstate = chainman.ActiveChainstate();
                return CVerifyDB().VerifyDB(
                    active_chainstate, chainman.GetParams().GetConsensus(), active_chainstate.CoinsTip(), check_level, check_depth) == VerifyDBResult::SUCCESS;
            },
        };
    }

    // Function to push back buried soft fork description.
    void PushBackBuriedSoftForkDesc(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::BuriedDeployment dep) {
        if (!DeploymentEnabled(chainman, dep)) return;

        UniValue rv(UniValue::VOBJ);
        rv.pushKV("type", "buried");
        rv.pushKV("active", DeploymentActiveAfter(blockindex, chainman, dep));
        rv.pushKV("height", chainman.GetConsensus().DeploymentHeight(dep));
        softforks.pushKV(DeploymentName(dep), rv);
    }

    // Function to get the name of the threshold state.
    std::string GetThresholdStateName(const ThresholdState state) {
        switch (state) {
            case ThresholdState::DEFINED: return "defined";
            case ThresholdState::STARTED: return "started";
            case ThresholdState::LOCKED_IN: return "locked_in";
            case ThresholdState::ACTIVE: return "active";
            case ThresholdState::FAILED: return "failed";
            default: return "invalid";
        }
    }

    // Function to create SIP9 information.
    UniValue CreateSip9Info(const ChainstateManager& chainman, const CBlockIndex* blockindex, Consensus::DeploymentPos id) {
        UniValue sip9(UniValue::VOBJ);

        // Get the next and current state for the specified deployment.
        const ThresholdState next_state = chainman.m_versionbitscache.State(blockindex, chainman.GetConsensus(), id);
        const ThresholdState current_state = chainman.m_versionbitscache.State(blockindex->pprev, chainman.GetConsensus(), id);
        
        // Check if there is a SIP9 signal in the current or previous block.
        const bool has_signal = (ThresholdState::STARTED == current_state || ThresholdState::LOCKED_IN == current_state);

        // SIP9 parameters
        if (has_signal) {
            sip9.pushKV("bit", chainman.GetConsensus().vDeployments[id].bit);
        }
        sip9.pushKV("start_time", chainman.GetConsensus().vDeployments[id].nStartTime);
        sip9.pushKV("timeout", chainman.GetConsensus().vDeployments[id].nTimeout);
        sip9.pushKV("min_activation_height", chainman.GetConsensus().vDeployments[id].min_activation_height);

        // SIP9 status
        sip9.pushKV("status", GetThresholdStateName(current_state));
        sip9.pushKV("since", chainman.m_versionbitscache.StateSinceHeight(blockindex->pprev, chainman.GetConsensus(), id));
        sip9.pushKV("status_next", GetThresholdStateName(next_state));

        // SIP9 signalling status, if applicable
        if (has_signal) {
            UniValue statsUV(UniValue::VOBJ);
            std::vector<bool> signals;
            SIP9Stats statsStruct = chainman.m_versionbitscache.Statistics(blockindex, chainman.GetConsensus(), id, &signals);
            statsUV.pushKV("period", statsStruct.period);
            statsUV.pushKV("elapsed", statsStruct.elapsed);
            statsUV.pushKV("count", statsStruct.count);
            
            if (ThresholdState::LOCKED_IN != current_state) {
                statsUV.pushKV("threshold", statsStruct.threshold);
                statsUV.pushKV("possible", statsStruct.possible);
            }
            
            sip9.pushKV("statistics", statsUV);

            std::string sig;
            sig.reserve(signals.size());
            for (const bool s : signals) {
                sig.push_back(s ? '#' : '-');
            }
            sip9.pushKV("signalling", sig);
        }

        return sip9;
    }

    // Function to push back SIP9 soft fork description.
    void PushBackSip9SoftForkDesc(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::DeploymentPos id) {
        // Check if the SIP9 deployment is enabled and a valid blockindex is provided.
        if (!DeploymentEnabled(chainman, id) || blockindex == nullptr) {
            return;
        }

        UniValue rv(UniValue::VOBJ);
        rv.pushKV("type", "sip9");

        // Get the next state for the specified deployment.
        const ThresholdState next_state = chainman.m_versionbitscache.State(blockindex, chainman.GetConsensus(), id);
        
        if (ThresholdState::ACTIVE == next_state) {
            rv.pushKV("height", chainman.m_versionbitscache.StateSinceHeight(blockindex, chainman.GetConsensus(), id));
        }
        
        rv.pushKV("active", ThresholdState::ACTIVE == next_state);
        rv.pushKV("sip9", CreateSip9Info(chainman, blockindex, id));

        softforks.pushKV(DeploymentName(id), rv);
    }

    // Function to create a blockchain info object.
    UniValue CreateBlockchainInfoObject(const ChainstateManager& chainman) {
        const CBlockIndex* tip = chainman.ActiveChainstate().m_chain.Tip();
        const int height = (tip != nullptr) ? tip->nHeight : -1;
        UniValue obj(UniValue::VOBJ);
        
        obj.pushKV("chain", chainman.GetParams().NetworkIDString());
        obj.pushKV("blocks", height);
        obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);
        
        if (tip != nullptr) {
            obj.pushKV("bestblockhash", tip->GetBlockHash().GetHex());
            obj.pushKV("difficulty", GetDifficulty(tip));
            obj.pushKV("time", tip->GetBlockTime());
            obj.pushKV("mediantime", tip->GetMedianTimePast());
            obj.pushKV("verificationprogress", GuessVerificationProgress(chainman.GetParams().TxData(), tip));
        } else {
            obj.pushKV("bestblockhash", "");
            obj.pushKV("difficulty", 0.0);
            obj.pushKV("time", 0);
            obj.pushKV("mediantime", 0);
            obj.pushKV("verificationprogress", 0.0);
        }
        
        obj.pushKV("initialblockdownload", chainman.ActiveChainstate().IsInitialBlockDownload());
        
        if (chainman.m_blockman.IsPruneMode()) {
            obj.pushKV("pruned", true);
            const CBlockIndex* firstStoredBlock = chainman.m_blockman.GetFirstStoredBlock(tip);
            
            if (firstStoredBlock != nullptr) {
                obj.pushKV("pruneheight", firstStoredBlock->nHeight);
            }
            
            const bool automaticPruning = (chainman.m_blockman.GetPruneTarget() != BlockManager::PRUNE_TARGET_MANUAL);
            obj.pushKV("automatic_pruning", automaticPruning);
            
            if (automaticPruning) {
                obj.pushKV("prune_target_size", chainman.m_blockman.GetPruneTarget());
            }
        } else {
            obj.pushKV("pruned", false);
        }
        
        obj.pushKV("warnings", GetWarnings(false).original);
        
        return obj;
    }

    // Function to get blockchain information.
    RPCH GetBlockchainInfo() {
        return RPCH{"getblockchaininfo",
            "Returns an object containing various state info regarding blockchain processing.\n",
            {},
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "chain", "current network name (main, test, signet, regtest)"},
                    {RPCResult::Type::NUM, "blocks", "the height of the most-work fully-validated chain. The genesis block has height 0"},
                    {RPCResult::Type::NUM, "headers", "the current number of headers we have validated"},
                    {RPCResult::Type::STR, "bestblockhash", "the hash of the currently best block"},
                    {RPCResult::Type::NUM, "difficulty", "the current difficulty"},
                    {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM, "verificationprogress", "estimate of verification progress [0..1]"},
                    {RPCResult::Type::BOOL, "initialblockdownload", "(debug information) estimate of whether this node is in Initial Block Download mode"},
                    {RPCResult::Type::STR_HEX, "chainwork", "total amount of work in active chain, in hexadecimal"},
                    {RPCResult::Type::NUM, "size_on_disk", "the estimated size of the block and undo files on disk"},
                    {RPCResult::Type::BOOL, "pruned", "if the blocks are subject to pruning"},
                    {RPCResult::Type::NUM, "pruneheight", /*optional=*/true, "height of the last block pruned, plus one (only present if pruning is enabled)"},
                    {RPCResult::Type::BOOL, "automatic_pruning", /*optional=*/true, "whether automatic pruning is enabled (only present if pruning is enabled)"},
                    {RPCResult::Type::NUM, "prune_target_size", /*optional=*/true, "the target size used by pruning (only present if automatic pruning is enabled)"},
                    {RPCResult::Type::STR, "warnings", "any network and blockchain warnings"},
                }},
            RPCExamples{
                HelpExampleCli("getblockchaininfo", "")
                + HelpExampleRpc("getblockchaininfo", "")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                UniValue obj = CreateBlockchainInfoObject(chainman);
                return obj;
            },
        };
    }

    namespace DeploymentTypes {
        // Function to define the BURIED deployment type.
        const std::string BURIED = "buried";
        // Function to define the SIP9 deployment type.
        const std::string SIP9 = "sip9";
    }

    // This function retrieves deployment information for a given block index and chain manager.
    UniValue GetDeploymentInfo(const CBlockIndex* blockindex, const ChainstateManager& chainman) {
        UniValue deployments(UniValue::VOBJ);

        // Loop through various deployment positions and types.
        auto pushDeploymentInfo = [&](Consensus::DeploymentPos id, const std::string& type) {
            // Check if the deployment is enabled in the chain manager.
            if (DeploymentEnabled(chainman, id)) {
                // Create a UniValue object to store deployment details.
                UniValue deployment(UniValue::VOBJ);
                
                // Set the 'type' field for the deployment.
                deployment.pushKV("type", type);
                
                // Get the current state of the deployment and set the 'active' field accordingly.
                const ThresholdState current_state = chainman.m_versionbitscache.State(blockindex, chainman.GetConsensus(), id);
                deployment.pushKV("active", current_state == ThresholdState::ACTIVE);
                
                // Set the 'height' field for the deployment, considering the threshold state.
                deployment.pushKV("height", (current_state == ThresholdState::BURIED) ? blockindex->nHeight : -1);
                
                // If the deployment type is SIP9, add SIP9-specific deployment information.
                if (type == DeploymentTypes::SIP9) {
                    deployment.pushKV("sip9", CreateSip9DeploymentInfo(id, blockindex, chainman));
                }
                
                // Add the deployment information to the 'deployments' UniValue object.
                deployments.pushKV(DeploymentName(id), deployment);
            }
        };

        // Call the pushDeploymentInfo function for each deployment type and position.
        pushDeploymentInfo(SPHINXConsensus::DEPLOYMENT_HEIGHTINCB, DeploymentTypes::BURIED);
        pushDeploymentInfo(SPHINXConsensus::DEPLOYMENT_DERSIG, DeploymentTypes::BURIED);
        pushDeploymentInfo(SPHINXConsensus::DEPLOYMENT_CLTV, DeploymentTypes::BURIED);
        pushDeploymentInfo(SPHINXConsensus::DEPLOYMENT_CSV, DeploymentTypes::BURIED);
        pushDeploymentInfo(SPHINXConsensus::DEPLOYMENT_SEGWIT, DeploymentTypes::BURIED);
        pushDeploymentInfo(SPHINXConsensus::DEPLOYMENT_TESTDUMMY, DeploymentTypes::BURIED);
        pushDeploymentInfo(SPHINXConsensus::DEPLOYMENT_TAPROOT, DeploymentTypes::BURIED);

        // Return the 'deployments' UniValue object containing all deployment information.
        return deployments;
    }

    // This function creates and returns Sip9 deployment information.
    UniValue CreateSip9DeploymentInfo(Consensus::DeploymentPos id, const CBlockIndex* blockindex, const ChainstateManager& chainman) {
        // Create a UniValue object to store Sip9 deployment information.
        UniValue sip9(UniValue::VOBJ);

        // Get the current state of the deployment.
        const ThresholdState current_state = chainman.m_versionbitscache.State(blockindex, chainman.GetConsensus(), id);

        // Get the next state of the deployment.
        const ThresholdState next_state = chainman.m_versionbitscache.State(blockindex->pprev, chainman.GetConsensus(), id);

        // Set various Sip9 deployment details.
        sip9.pushKV("start_time", chainman.GetConsensus().vDeployments[id].nStartTime);
        sip9.pushKV("timeout", chainman.GetConsensus().vDeployments[id].nTimeout);
        sip9.pushKV("min_activation_height", chainman.GetConsensus().vDeployments[id].min_activation_height);
        sip9.pushKV("status", GetStateName(current_state));
        sip9.pushKV("since", chainman.m_versionbitscache.StateSinceHeight(blockindex->pprev, chainman.GetConsensus(), id));
        sip9.pushKV("status_next", GetStateName(next_state));

        // Check if the deployment is in STARTED or LOCKED_IN state.
        if (current_state == ThresholdState::STARTED || current_state == ThresholdState::LOCKED_IN) {
            sip9.pushKV("bit", chainman.GetConsensus().vDeployments[id].bit);

            // Check if the deployment is not yet LOCKED_IN.
            if (current_state != ThresholdState::LOCKED_IN) {
                // Create a UniValue object to store SIP9 statistics.
                UniValue statistics(UniValue::VOBJ);
                std::vector<bool> signals;
                
                // Get and set SIP9 statistics.
                SIP9Stats stats = chainman.m_versionbitscache.Statistics(blockindex, chainman.GetConsensus(), id, &signals);
                statistics.pushKV("period", stats.period);
                statistics.pushKV("elapsed", stats.elapsed);
                statistics.pushKV("count", stats.count);
                statistics.pushKV("threshold", stats.threshold);
                statistics.pushKV("possible", stats.possible);
                sip9.pushKV("statistics", statistics);

                // Generate a signaling string.
                std::string signalling;
                
                // Create a signaling string based on the signals received.
                for (const bool signal : signals) {
                    signalling += signal ? "#" : "-";
                }
                sip9.pushKV("signalling", signalling);
            }
        }

        // Return the Sip9 deployment information.
        return sip9;
    }

    // This function defines the "getdeploymentinfo" RPC method.
    RPCH GetDeploymentInfoRPC() {
        return RPCH{"getdeploymentinfo",
            "Returns an object containing various state info regarding deployments of consensus changes.",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Default{"hash of current chain tip"}, "The block hash at which to query deployment state"},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "hash", "requested block hash (or tip)"},
                    {RPCResult::Type::NUM, "height", "requested block height (or tip)"},
                    {RPCResult::Type::OBJ_DYN, "deployments", "", RPCHelpForDeployment}
                }
            },
            RPCExamples{ HelpExampleCli("getdeploymentinfo", "") + HelpExampleRpc("getdeploymentinfo", "") },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                const ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                const Chainstate& active_chainstate = chainman.ActiveChainstate();
                
                // Get the block index for the requested block hash or tip.
                const CBlockIndex* blockindex;
                if (request.params[0].isNull()) {
                    blockindex = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
                } else {
                    const SPHINXHash::SPHINX_256 hash(ParseHashV(request.params[0], "blockhash"));
                    blockindex = chainman.m_blockman.LookupBlockIndex(hash);
                    if (!blockindex) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                    }
                }
                
                // Create a UniValue object to store deployment information for the specified block.
                UniValue deploymentInfo(UniValue::VOBJ);
                deploymentInfo.pushKV("hash", blockindex->GetBlockHash().ToString());
                deploymentInfo.pushKV("height", blockindex->nHeight);
                deploymentInfo.pushKV("deployments", GetDeploymentInfo(blockindex, chainman));
                
                return deploymentInfo;
            },
        };
    }

    // This struct represents information about the chain tip.
    struct ChainTipInfo {
        int height;
        std::string hash;
        int branchLen;
        std::string status;
    };

    // This struct defines a comparator to compare CBlockIndex objects by their height.
    struct CompareBlocksByHeight {
        bool operator()(const CBlockIndex* a, const CBlockIndex* b) const {
            // Compare CBlockIndex objects based on their height.
            if (a->nHeight != b->nHeight)
                return (a->nHeight > b->nHeight);
            return a < b;
        }
    };

    // This function finds the chain tips in the blockchain.
    std::set<const CBlockIndex*, CompareBlocksByHeight> FindChainTips(const ChainstateManager& chainman) {
        std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
        std::set<const CBlockIndex*> setOrphans;
        std::set<const CBlockIndex*> setPrevs;
        CChain& activeChain = chainman.ActiveChain();
        
        // Iterate through all block indexes in the blockchain.
        for (const auto& [_, blockIndex] : chainman.BlockIndex()) {
            // Check if the block is not part of the active chain.
            if (!activeChain.Contains(&blockIndex)) {
                setOrphans.insert(&blockIndex);
                setPrevs.insert(blockIndex.pprev);
            }
        }
        
        // Identify the chain tips among the orphan blocks.
        for (auto it = setOrphans.begin(); it != setOrphans.end(); ++it) {
            if (setPrevs.erase(*it) == 0) {
                setTips.insert(*it);
            }
        }
        
        // Insert the tip of the active chain into the set of chain tips.
        setTips.insert(activeChain.Tip());
        return setTips;
    }

    // This function determines the status of a block in relation to the active chain.
    std::string GetChainTipStatus(const CBlockIndex* block, const CChain& activeChain) {
        // Check if the block is part of the active chain.
        if (activeChain.Contains(block)) {
            return "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            return "invalid";
        } else if (!block->HaveTxsDownloaded()) {
            return "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            return "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            return "valid-headers";
        } else {
            return "unknown";
        }
    }

    // This function retrieves information about the chain tips.
    std::vector<ChainTipInfo> GetChainTipsInfo(const std::set<const CBlockIndex*, CompareBlocksByHeight>& chainTips, const CChain& activeChain) {
        std::vector<ChainTipInfo> tipsInfo;
        
        // Iterate through the set of chain tips and gather information for each tip.
        for (const CBlockIndex* block : chainTips) {
            ChainTipInfo info;
            info.height = block->nHeight;
            info.hash = block->phashBlock->GetHex();
            
            // Calculate the length of the branch from the tip to the active chain.
            info.branchLen = block->nHeight - activeChain.FindFork(block)->nHeight;
            
            // Determine the status of the chain tip.
            info.status = GetChainTipStatus(block, activeChain);
            
            // Add the collected information to the vector.
            tipsInfo.push_back(info);
        }
        
        return tipsInfo;
    }

    // This function defines the "getchaintips" RPC method.
    RPCH GetChainTipsRPC() {
        return RPCH{"getchaintips",
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n",
            {},
            RPCResult{
                RPCResult::Type::ARR, "", "",
                {{RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "height", "height of the chain tip"},
                        {RPCResult::Type::STR_HEX, "hash", "block hash of the tip"},
                        {RPCResult::Type::NUM, "branchlen", "zero for main chain, otherwise length of branch connecting the tip to the main chain"},
                        {RPCResult::Type::STR, "status", "status of the chain, \"active\" for the main chain\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid"},
                    }}}},
            RPCExamples{
                HelpExampleCli("getchaintips", "")
        + HelpExampleRpc("getchaintips", "")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                // Get the ChainstateManager.
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                // Acquire a lock on the blockchain.
                LOCK(cs_main);
                // Get the active chain.
                const CChain& activeChain = chainman.ActiveChain();
                // Find all chain tips.
                std::set<const CBlockIndex*, CompareBlocksByHeight> chainTips = FindChainTips(chainman);
                // Get information about the chain tips.
                std::vector<ChainTipInfo> tipsInfo = GetChainTipsInfo(chainTips, activeChain);
                // Create a UniValue array to store the results.
                UniValue res(UniValue::VARR);
                // Convert chain tip information to UniValue objects and add them to the result array.
                for (const ChainTipInfo& info : tipsInfo) {
                    UniValue obj(UniValue::VOBJ);
                    obj.pushKV("height", info.height);
                    obj.pushKV("hash", info.hash);
                    obj.pushKV("branchlen", info.branchLen);
                    obj.pushKV("status", info.status);
                    res.push_back(obj);
                }
                // Return the result array.
                return res;
            },
        };
    }

    // This function handles a precious block, marking it as valid and ensuring its integrity.
    UniValue HandlePreciousBlock(const SPHINXHash::SPHINX_256& blockHash, ChainstateManager& chainman) {
        CBlockIndex* pblockindex;

        {
            // Acquire a lock on the blockchain.
            LOCK(cs_main);
            // Lookup the block index based on the provided block hash.
            pblockindex = chainman.m_blockman.LookupBlockIndex(blockHash);
            // Check if the block index exists.
            if (!pblockindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
        }
        
        // Create a BlockValidationState object to track the validation state of the precious block.
        BlockValidationState state;
        // Mark the block as precious and validate it.
        chainman.ActiveChainstate().PreciousBlock(state, pblockindex);
        
        // Check if the block validation state is valid.
        if (!state.IsValid()) {
            throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
        }

        // Return a NULL UniValue indicating successful processing.
        return UniValue::VNULL;
    }

    // This function defines the "preciousblock" RPC method.
    RPCH PreciousBlockRPC() {
        return RPCH{"preciousblock",
            "\nTreats a block as if it were received before others with the same work.\n"
            "\nA later preciousblock call can override the effect of an earlier one.\n"
            "\nThe effects of preciousblock are not retained across restarts.\n",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as precious"},
            },
            RPCResult{RPCResult::Type::NONE, "", ""},
            RPCExamples{
                HelpExampleCli("preciousblock", "\"blockhash\"")
        + HelpExampleRpc("preciousblock", "\"blockhash\"")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                // Parse the block hash from the RPC request.
                SPHINXHash::SPHINX_256 hash(ParseHashV(request.params[0], "blockhash"));
                // Get the ChainstateManager.
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                // Handle the specified block as precious.
                return HandlePreciousBlock(hash, chainman);
            },
        };
    }

    // This function handles the invalidation of a block.
    UniValue HandleInvalidateBlock(const SPHINXHash::SPHINX_256& blockHash, ChainstateManager& chainman) {
        BlockValidationState state;

        {
            // Acquire a lock on the blockchain.
            LOCK(cs_main);
            // Lookup the block index based on the provided block hash.
            CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(blockHash);
            // Check if the block index exists.
            if (!pblockindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
            // Invalidate the specified block in the active chainstate.
            chainman.ActiveChainstate().InvalidateBlock(state, pblockindex);
            // If the block is successfully invalidated, activate the best chain.
            if (state.IsValid()) {
                chainman.ActiveChainstate().ActivateBestChain(state);
            }
        }
        // Check if the block invalidation state is valid.
        if (!state.IsValid()) {
            throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
        }

        // Return a NULL UniValue indicating successful processing.
        return UniValue::VNULL;
    }

    // This function defines the "invalidateblock" RPC method.
    RPCH InvalidateBlockRPC() {
        return RPCH{"invalidateblock",
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as invalid"},
            },
            RPCResult{RPCResult::Type::NONE, "", ""},
            RPCExamples{
                HelpExampleCli("invalidateblock", "\"blockhash\"")
        + HelpExampleRpc("invalidateblock", "\"blockhash\"")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                // Parse the block hash from the RPC request.
                SPHINXHash::SPHINX_256 hash(ParseHashV(request.params[0], "blockhash"));
                // Get the ChainstateManager.
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                // Handle the specified block as invalid.
                return HandleInvalidateBlock(hash, chainman);
            },
        };
    }

    // This function handles reconsideration of a block.
    UniValue HandleReconsiderBlock(const SPHINXHash::SPHINX_256& blockHash, ChainstateManager& chainman) {
        {
            // Acquire a lock on the blockchain.
            LOCK(cs_main);
            // Lookup the block index based on the provided block hash.
            CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(blockHash);
            // Check if the block index exists.
            if (!pblockindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
            // Reset block failure flags for the specified block in the active chainstate.
            chainman.ActiveChainstate().ResetBlockFailureFlags(pblockindex);
        }
        // Create a BlockValidationState object to track the validation state.
        BlockValidationState state;
        // Activate the best chain, potentially revalidating the reconsidered block.
        chainman.ActiveChainstate().ActivateBestChain(state);
        // Check if the block validation state is valid.
        if (!state.IsValid()) {
            throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
        }
        // Return a NULL UniValue indicating successful processing.
        return UniValue::VNULL;
    }

    // This function defines the "reconsiderblock" RPC method.
    RPCH ReconsiderBlockRPC() {
        return RPCH{"reconsiderblock",
            "\nRemoves invalidity status of a block, its ancestors and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to reconsider"},
            },
            RPCResult{RPCResult::Type::NONE, "", ""},
            RPCExamples{
                HelpExampleCli("reconsiderblock", "\"blockhash\"")
        + HelpExampleRpc("reconsiderblock", "\"blockhash\"")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                // Parse the block hash from the RPC request.
                SPHINXHash::SPHINX_256 hash(ParseHashV(request.params[0], "blockhash"));
                // Get the ChainstateManager.
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                // Handle the specified block as reconsidered.
                return HandleReconsiderBlock(hash, chainman);
            },
        };
    }

    // This function handles the calculation of chain transaction statistics.
    UniValue HandleGetChainTxStats(int blockcount, const CBlockIndex* pindex) {
        UniValue ret(UniValue::VOBJ);
        ret.pushKV("time", (int64_t)pindex->nTimestamp);
        ret.pushKV("txcount", (int64_t)pindex->nChainTx);
        ret.pushKV("window_final_block_hash", pindex->GetBlockHash().GetHex());
        ret.pushKV("window_final_block_height", pindex->nHeight);
        ret.pushKV("window_block_count", blockcount);
        // Calculate additional statistics if there are blocks in the window.
        if (blockcount > 0) {
            const CBlockIndex& past_block{*CHECK_NONFATAL(pindex->GetAncestor(pindex->nHeight - blockcount))};
            const int64_t nTimeDifficultly{pindex->GetMedianTimePast() - past_block.GetMedianTimePast()};
            const int nTxDiff = pindex->nChainTx - past_block.nChainTx;

            ret.pushKV("window_tx_count", nTxDiff);
            ret.pushKV("window_interval", nTimeDifficultly);
            // Calculate and include the transaction rate if the time difference is positive.
            if (nTimeDifficultly > 0) {
                ret.pushKV("txrate", ((double)nTxDiff) / nTimeDifficultly);
            }
        }

        return ret;
    }

    // This function defines the "getchaintxstats" RPC method.
    RPCH GetChainTxStatsRPC() {
        return RPCH{"getchaintxstats",
            "\nCompute statistics about the total number and rate of transactions in the chain.\n",
            {
                {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{"one month"}, "Size of the window in number of blocks"},
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "The hash of the block that ends the window."},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM_TIME, "time", "The timestamp for the final block in the window, expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM, "txcount", "The total number of transactions in the chain up to that point"},
                    {RPCResult::Type::STR_HEX, "window_final_block_hash", "The hash of the final block in the window"},
                    {RPCResult::Type::NUM, "window_final_block_height", "The height of the final block in the window."},
                    {RPCResult::Type::NUM, "window_block_count", "Size of the window in number of blocks"},
                    {RPCResult::Type::NUM, "window_tx_count", /*optional=*/true, "The number of transactions in the window. Only returned if \"window_block_count\" is > 0"},
                    {RPCResult::Type::NUM, "window_interval", /*optional=*/true, "The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0"},
                    {RPCResult::Type::NUM, "txrate", /*optional=*/true, "The average rate of transactions per second in the window. Only returned if \"window_interval\" is > 0"},
                }},
            RPCExamples{
                HelpExampleCli("getchaintxstats", "")
        + HelpExampleRpc("getchaintxstats", "2016")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                // Get the ChainstateManager.
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                const CBlockIndex* pindex;
                // Check if the block hash is provided, otherwise use the chain tip.
                if (request.params[1].isNull()) {
                    LOCK(cs_main);
                    pindex = chainman.ActiveChain().Tip();
                } else {
                    SPHINXHash::SPHINX_256 hash(ParseHashV(request.params[1], "blockhash"));
                    LOCK(cs_main);
                    // Lookup the block index based on the provided block hash.
                    pindex = chainman.m_blockman.LookupBlockIndex(hash);
                    // Check if the block index exists and is in the main chain.
                    if (!pindex) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                    }
                    if (!chainman.ActiveChain().Contains(pindex)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in the main chain");
                    }
                }
                // Check if the block count is provided, otherwise use a default value.
                int blockcount;
                if (request.params[0].isNull()) {
                    blockcount = std::max(0, std::min(blockcount, pindex->nHeight - 1));
                } else {
                    blockcount = request.params[0].getInt<int>();
                    // Validate the provided block count.
                    if (blockcount < 0 || (blockcount > 0 && blockcount >= pindex->nHeight)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: should be between 0 and the block's height - 1");
                    }
                }
                // Calculate and return chain transaction statistics.
                return HandleGetChainTxStats(blockcount, pindex);
            },
        };
    }

    // Calculate the truncated median of a vector of scores.
    template<typename T>
    T CalculateTruncatedMedian(std::vector<T>& scores) {
        size_t size = scores.size();
        if (size == 0) {
            return 0;
        }
        std::sort(scores.begin(), scores.end());
        if (size % 2 == 0) {
            return (scores[size / 2 - 1] + scores[size / 2]) / 2;
        } else {
            return scores[size / 2];
        }
    }

    // Calculate percentiles of scores weighted by a total weight.
    void CalculatePercentilesByWeight(CAmount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<CAmount, int64_t>>& scores, int64_t total_weight) {
        if (scores.empty()) {
            return;
        }
        std::sort(scores.begin(), scores.end());

        // Define the percentiles: 10th, 25th, 50th, 75th, and 90th percentile weight units.
        const double weights[NUM_GETBLOCKSTATS_PERCENTILES] = {
            total_weight / 10.0, total_weight / 4.0, total_weight / 2.0, (total_weight * 3.0) / 4.0, (total_weight * 9.0) / 10.0
        };

        int64_t next_percentile_index = 0;
        int64_t cumulative_weight = 0;

        // Calculate percentiles by weight.
        for (const auto& element : scores) {
            cumulative_weight += element.second;
            while (next_percentile_index < NUM_GETBLOCKSTATS_PERCENTILES && cumulative_weight >= weights[next_percentile_index]) {
                result[next_percentile_index] = element.first;
                ++next_percentile_index;
            }
        }

        // Fill any remaining percentiles with the last value.
        for (int64_t i = next_percentile_index; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
            result[i] = scores.back().first;
        }
    }

    // Check if a set contains all of the specified keys.
    template<typename T>
    bool SetHasKeys(const std::set<T>& set) {
        return false;
    }

    // Check if a set contains all of the specified keys.
    template<typename T, typename Tk, typename... Args>
    bool SetHasKeys(const std::set<T>& set, const Tk& key, const Args&... args) {
        return (set.count(key) != 0) || SetHasKeys(set, args...);
    }
namespace RPC {
    // Structure to store block statistics.
    struct BlockStats {
        // Average fee in the block.
        CAmount avgfee = 0;

        // Average feerate in the block.
        CAmount avgfeerate = 0;

        // Average transaction size in the block.
        int64_t avgtxsize = 0;

        // Block hash in hexadecimal.
        std::string blockhash = "";

        // Array of feerate percentiles.
        std::vector<CAmount> feerate_percentiles;

        // Height of the block in the blockchain.
        int64_t height = 0;

        // Total number of inputs in the block.
        int64_t ins = 0;

        // Maximum fee in the block.
        CAmount maxfee = 0;

        // Maximum feerate in the block.
        CAmount maxfeerate = 0;

        // Maximum transaction size in the block.
        int64_t maxtxsize = 0;

        // Median fee in the block.
        CAmount medianfee = 0;

        // Median time of the block.
        int64_t mediantime = 0;

        // Median transaction size in the block.
        int64_t mediantxsize = 0;

        // Minimum fee in the block.
        CAmount minfee = 0;

        // Minimum feerate in the block.
        CAmount minfeerate = 0;

        // Minimum transaction size in the block.
        int64_t mintxsize = 0;

        // Total number of outputs in the block.
        int64_t outs = 0;

        // Subsidy in the block.
        CAmount subsidy = 0;

        // Total size of witness data in the block.
        int64_t swtotal_size = 0;

        // Total weight of witness transactions in the block.
        int64_t swtotal_weight = 0;

        // Number of witness transactions in the block.
        int64_t swtxs = 0;

        // Timestamp of the block.
        int64_t time = 0;

        // Total value of all outputs in the block.
        CAmount total_out = 0;

        // Total size of all transactions in the block.
        int64_t total_size = 0;

        // Total weight of all transactions in the block.
        int64_t total_weight = 0;

        // Total fees in the block.
        CAmount totalfee = 0;

        // Total number of transactions in the block.
        int64_t txs = 0;

        // UTXO increase in the block.
        int64_t utxo_increase = 0;

        // UTXO size increase in the block.
        int64_t utxo_size_inc = 0;

        // Actual UTXO increase in the block.
        int64_t utxo_increase_actual = 0;

        // Actual UTXO size increase in the block.
        int64_t utxo_size_inc_actual = 0;
    };

    // Calculate block statistics based on the provided block index and chain manager.
    static BlockStats CalculateBlockStats(const CBlockIndex& pindex, const ChainstateManager& chainman) {
        const CBlock& block = GetBlockChecked(chainman.m_blockman, &pindex);
        const CBlockUndo& blockUndo = GetUndoChecked(chainman.m_blockman, &pindex);
        BlockStats stats;
        stats.blockhash = pindex.GetBlockHash().GetHex();
        stats.height = pindex.nHeight;

        for (size_t i = 0; i < block.vtx.size(); ++i) {
            const auto& tx = block.vtx.at(i);

            if (tx->IsCoinBase()) {
                continue;
            }

            // Increase the total number of inputs.
            stats.ins += tx->vin.size();

            // Increase the total number of transactions.
            stats.txs++;

            CAmount tx_total_out = 0;
            for (const CTxOut& out : tx->vout) {
                tx_total_out += out.nValue;

                // Increase the total number of outputs.
                stats.outs++;

                // Calculate the size of the output and increase UTXO size.
                size_t out_size = GetSerializeSize(out, PROTOCOL_VERSION) + PER_UTXO_OVERHEAD;
                stats.utxo_size_inc += out_size;

                // Check conditions for UTXO increase.
                if (pindex.nHeight != 0 && (!IsSIP30Repeat(pindex) || !tx->IsCoinBase()) && !out.scriptPubKey.IsUnspendable()) {
                    stats.utxo_increase++;
                    stats.utxo_size_inc_actual += out_size;
                }
            }

            // Calculate transaction fees and feerates.
            if (!tx->IsCoinBase()) {
                const auto& txundo = blockUndo.vtxundo.at(i - 1);

                CAmount tx_total_in = 0;
                for (const Coin& coin : txundo.vprevout) {
                    const CTxOut& prevoutput = coin.out;
                    tx_total_in += prevoutput.nValue;

                    // Calculate the size of the previous output and reduce UTXO size.
                    size_t prevout_size = GetSerializeSize(prevoutput, PROTOCOL_VERSION) + PER_UTXO_OVERHEAD;
                    stats.utxo_size_inc -= prevout_size;
                    stats.utxo_size_inc_actual -= prevout_size;
                }

                CAmount txfee = tx_total_in - tx_total_out;
                CHECK_NONFATAL(SPXRange(txfee));
                stats.maxfee = std::max(stats.maxfee, txfee);
                stats.minfee = std::min(stats.minfee, txfee);
                stats.totalfee += txfee;

                CAmount feerate = (txfee * WITNESS_SCALE_FACTOR) / GetTransactionWeight(*tx);
                stats.maxfeerate = std::max(stats.maxfeerate, feerate);
                stats.minfeerate = std::min(stats.minfeerate, feerate);
                stats.feerate_percentiles.push_back(feerate);
            }

            // Calculate transaction size statistics.
            if (!tx->IsCoinBase() && i > 0) {
                int64_t tx_size = tx->GetTotalSize();
                stats.maxtxsize = std::max(stats.maxtxsize, tx_size);
                stats.mintxsize = std::min(stats.mintxsize, tx_size);
                stats.total_size += tx_size;

                if (tx->HasWitness()) {
                    stats.swtxs++;
                    stats.swtotal_size += tx_size;
                    stats.swtotal_weight += GetTransactionWeight(*tx);
                }
            }
        

            // Calculate feerate percentiles.
            if (!stats.feerate_percentiles.empty()) {
                CalculatePercentilesByWeight(stats.feerate_percentiles, stats.feerate_percentiles, stats.total_weight);
            }

            return stats;
        }

        // Function
        static UniValue GetBlockStatsResult(const BlockStats& stats) {
            UniValue result(UniValue::VOBJ);
            result.pushKV("avgfee", (stats.txs > 1) ? stats.totalfee / (stats.txs - 1) : 0);
            result.pushKV("avgfeerate", stats.total_weight ? (stats.totalfee * WITNESS_SCALE_FACTOR) / stats.total_weight : 0);
            result.pushKV("avgtxsize", (stats.txs > 1) ? stats.total_size / (stats.txs - 1) : 0);
            result.pushKV("blockhash", stats.blockhash);
            result.pushKV("feerate_percentiles", stats.feerate_percentiles);
            result.pushKV("height", stats.height);
            result.pushKV("ins", stats.ins);
            result.pushKV("maxfee", stats.maxfee);
            result.pushKV("maxfeerate", stats.maxfeerate);
            result.pushKV("maxtxsize", stats.maxtxsize);
            result.pushKV("medianfee", stats.medianfee);
            result.pushKV("mediantime", stats.mediantime);
            result.pushKV("mediantxsize", stats.mediantxsize);
            result.pushKV("minfee", stats.minfee);
            result.pushKV("minfeerate", stats.minfeerate);
            result.pushKV("mintxsize", stats.mintxsize);
            result.pushKV("outs", stats.outs);
            result.pushKV("subsidy", GetBlockSubsidy(stats.height, chainman.GetParams().GetConsensus()));
            result.pushKV("swtotal_size", stats.swtotal_size);
            result.pushKV("swtotal_weight", stats.swtotal_weight);
            result.pushKV("swtxs", stats.swtxs);
            result.pushKV("time", stats.time);
            result.pushKV("total_out", stats.total_out);
            result.pushKV("total_size", stats.total_size);
            result.pushKV("total_weight", stats.total_weight);
            result.pushKV("totalfee", stats.totalfee);
            result.pushKV("txs", stats.txs);
            result.pushKV("utxo_increase", stats.utxo_increase);
            result.pushKV("utxo_size_inc", stats.utxo_size_inc);
            result.pushKV("utxo_increase_actual", stats.utxo_increase_actual);
            result.pushKV("utxo_size_inc_actual", stats.utxo_size_inc_actual);
            return result;
        }

        static UniValue GetBlockStats(const JSONRPCRequest& request, ChainstateManager& chainman) {
            const CBlockIndex& pindex = *CHECK_NONFATAL(ParseHashOrHeight(request.params[0], chainman));
            std::set<std::string> selectedStats;

            if (!request.params[1].isNull()) {
                const UniValue& statsArray = request.params[1].get_array();
                for (const UniValue& stat : statsArray) {
                    selectedStats.insert(stat.get_str());
                }
            }

            const BlockStats stats = CalculateBlockStats(pindex, chainman);

            if (selectedStats.empty()) {
                return GetBlockStatsResult(stats);
            }

            UniValue result(UniValue::VOBJ);
            for (const std::string& selectedStat : selectedStats) {
                const UniValue& value = GetBlockStatsResult(stats)[selectedStat];
                if (value.isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid selected statistic '%s'", selectedStat));
                }
                result.pushKV(selectedStat, value);
            }

            return result;
        }

        RPCH GetBlockStatsHelp() {
            return RPCH{
                "getblockstats",
                "\nCompute per-block statistics for a given window. All amounts are in satoshis."
                "It won't work for some heights with pruning.\n",
                {
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block hash or height of the target block",
                        RPCArgOptions{
                            .skip_type_check = true,
                            .type_str = {"", "string or numeric"},
                        }},
                    {"stats", RPCArg::Type::ARR, RPCArg::DefaultHint{"all values"}, "Values to plot (see result below)",
                        {
                            {"height", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                            {"time", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                        },
                        RPCArgOptions{.oneline_description = "stats"}},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "avgfee", /*optional=*/true, "Average fee in the block"},
                        {RPCResult::Type::NUM, "avgfeerate", /*optional=*/true, "Average feerate (in satoshis per virtual byte)"},
                        {RPCResult::Type::NUM, "avgtxsize", /*optional=*/true, "Average transaction size"},
                        {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash (to check for potential reorgs)"},
                        {RPCResult::Type::ARR_FIXED, "feerate_percentiles", /*optional=*/true, "Feerates at the 10th, 25th, 50th, 75th, and 90th percentile weight unit (in satoshis per virtual byte)",
                            {
                                {RPCResult::Type::NUM, "10th_percentile_feerate", "The 10th percentile feerate"},
                                {RPCResult::Type::NUM, "25th_percentile_feerate", "The 25th percentile feerate"},
                                {RPCResult::Type::NUM, "50th_percentile_feerate", "The 50th percentile feerate"},
                                {RPCResult::Type::NUM, "75th_percentile_feerate", "The 75th percentile feerate"},
                                {RPCResult::Type::NUM, "90th_percentile_feerate", "The 90th percentile feerate"},
                            }},
                        {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the block"},
                        {RPCResult::Type::NUM, "ins", /*optional=*/true, "The number of inputs (excluding coinbase)"},
                        {RPCResult::Type::NUM, "maxfee", /*optional=*/true, "Maximum fee in the block"},
                        {RPCResult::Type::NUM, "maxfeerate", /*optional=*/true, "Maximum feerate (in satoshis per virtual byte)"},
                        {RPCResult::Type::NUM, "maxtxsize", /*optional=*/true, "Maximum transaction size"},
                        {RPCResult::Type::NUM, "medianfee", /*optional=*/true, "Truncated median fee in the block"},
                        {RPCResult::Type::NUM, "mediantime", /*optional=*/true, "The block median time past"},
                        {RPCResult::Type::NUM, "mediantxsize", /*optional=*/true, "Truncated median transaction size"},
                        {RPCResult::Type::NUM, "minfee", /*optional=*/true, "Minimum fee in the block"},
                        {RPCResult::Type::NUM, "minfeerate", /*optional=*/true, "Minimum feerate (in satoshis per virtual byte)"},
                        {RPCResult::Type::NUM, "mintxsize", /*optional=*/true, "Minimum transaction size"},
                        {RPCResult::Type::NUM, "outs", /*optional=*/true, "The number of outputs"},
                        {RPCResult::Type::NUM, "subsidy", /*optional=*/true, "The block subsidy"},
                        {RPCResult::Type::NUM, "swtotal_size", /*optional=*/true, "Total size of all segwit transactions"},
                        {RPCResult::Type::NUM, "swtotal_weight", /*optional=*/true, "Total weight of all segwit transactions"},
                        {RPCResult::Type::NUM, "swtxs", /*optional=*/true, "The number of segwit transactions"},
                        {RPCResult::Type::NUM, "time", /*optional=*/true, "The block time"},
                        {RPCResult::Type::NUM, "total_out", /*optional=*/true, "Total amount in all outputs (excluding coinbase and thus reward [i.e., subsidy + totalfee])"},
                        {RPCResult::Type::NUM, "total_size", /*optional=*/true, "Total size of all non-coinbase transactions"},
                        {RPCResult::Type::NUM, "total_weight", /*optional=*/true, "Total weight of all non-coinbase transactions"},
                        {RPCResult::Type::NUM, "totalfee", /*optional=*/true, "The fee total"},
                        {RPCResult::Type::NUM, "txs", /*optional=*/true, "The number of transactions (including coinbase)"},
                        {RPCResult::Type::NUM, "utxo_increase", /*optional=*/true, "The increase/decrease in the number of unspent outputs (not discounting op_return and similar)"},
                        {RPCResult::Type::NUM, "utxo_size_inc", /*optional=*/true, "The increase/decrease in size for the utxo index (not discounting op_return and similar)"},
                        {RPCResult::Type::NUM, "utxo_increase_actual", /*optional=*/true, "The increase/decrease in the number of unspent outputs, not counting unspendables"},
                        {RPCResult::Type::NUM, "utxo_size_inc_actual", /*optional=*/true, "The increase/decrease in size for the utxo index, not counting unspendables"},
                    }},
                RPCExamples{
                    HelpExampleCli("getblockstats", R"('"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"' '["minfeerate","avgfeerate"]')") +
                    HelpExampleCli("getblockstats", R"(1000 '["minfeerate","avgfeerate"]')") +
                    HelpExampleRpc("getblockstats", R"("00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09", ["minfeerate","avgfeerate"])") +
                    HelpExampleRpc("getblockstats", R"(1000, ["minfeerate","avgfeerate"])")
                },
                [&](const RPCHMan& self, const JSONRPCRequest& request) -> UniValue {
                    return GetBlockStats(request, EnsureAnyChainman(request.context));
                },
            };
        }

    } // namespace RPC

    namespace {
        using ProgressCallback = std::function<void(int)>;
        using InterruptCallback = std::function<void()>;

        bool FindScriptPubKey(
            std::atomic<int>& scan_progress,
            const std::atomic<bool>& should_abort,
            int64_t& count,
            CCoinsViewCursor* cursor,
            const std::set<CScript>& needles,
            std::map<COutPoint, Coin>& out_results,
            ProgressCallback progress_callback,
            InterruptCallback interruption_callback
        ) {
            scan_progress = 0;
            count = 0;

            while (cursor->Valid()) {
                COutPoint key;
                Coin coin;

                if (!cursor->GetKey(key) || !cursor->GetValue(coin)) {
                    return false;
                }

                if (++count % 8192 == 0) {
                    interruption_callback();
                    if (should_abort) {
                        // Allow aborting the scan via the should_abort flag
                        return false;
                    }
                }

                if (count % 256 == 0) {
                    // Update progress every 256 items
                    uint32_t high = 0x100 * *key.hash.begin() + *(key.hash.begin() + 1);
                    scan_progress = static_cast<int>(high * 100.0 / 65536.0 + 0.5);
                    progress_callback(scan_progress.load());
                }

                if (needles.count(coin.out.scriptPubKey)) {
                    out_results.emplace(key, coin);
                }

                cursor->Next();
            }

            scan_progress = 100;
            progress_callback(scan_progress.load());
            return true;
        }
    };

    class CoinsViewScanReserver {
    public:
        CoinsViewScanReserver() {
            if (g_scan_in_progress.exchange(true)) {
                return;
            }
            CHECK_NONFATAL(g_scan_progress == 0);
            m_could_reserve = true;
        }

        bool reserve() {
            return m_could_reserve;
        }

        ~CoinsViewScanReserver() {
            if (m_could_reserve) {
                g_scan_in_progress = false;
                g_scan_progress = 0;
            }
        }

    private:
        bool m_could_reserve{false};
    };

    enum class ScanAction { START, ABORT, STATUS };

    static const auto scan_action_arg_desc = RPCArg{
        "action", RPCArg::Type::STR, RPCArg::Optional::NO, "The action to execute\n"
        "\"start\" for starting a scan\n"
        "\"abort\" for aborting the current scan (returns true when abort was successful)\n"
        "\"status\" for progress report (in %) of the current scan"
    };

    struct ScanObject {
        std::string desc;
        std::pair<int, int> range{1000, 1000};
    };

    using ScanObjectDescriptor = std::variant<std::string, ScanObject>;

    static const auto scan_objects_arg_desc = RPCArg{
        "scanobjects", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of scan objects. Required for \"start\" action\n"
        "Every scan object is either a string descriptor or an object:",
        {
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with output descriptor and metadata",
                {
                    {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                    {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "The range of HD chain indexes to explore (either end or [begin,end])"},
                }},
        },
        RPCArgOptions{.oneline_description="[scanobjects,...]"},
    };

    static const auto scan_result_abort = RPCResult{
        "when action=='abort'", RPCResult::Type::BOOL, "success",
        "True if scan will be aborted (not necessarily before this RPC returns), or false if there is no scan to abort"
    };

    static const auto scan_result_status_none = RPCResult{
        "when action=='status' and no scan is in progress - possibly already completed", RPCResult::Type::NONE, "", ""
    };

    static const auto scan_result_status_some = RPCResult{
        "when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "",
        {{RPCResult::Type::NUM, "progress", "Approximate percent complete"},}
    };

    enum class ScanAction { START, ABORT, STATUS };

    struct ScanObject {
        std::string desc;
        std::pair<int, int> range{1000, 1000};
    };

    class CoinsViewScanReserver {
    public:
        CoinsViewScanReserver() {
            if (g_scan_in_progress.exchange(true)) {
                return;
            }
            CHECK_NONFATAL(g_scan_progress == 0);
            m_could_reserve = true;
        }

        bool reserve() {
            return m_could_reserve;
        }

        ~CoinsViewScanReserver() {
            if (m_could_reserve) {
                g_scan_in_progress = false;
                g_scan_progress = 0;
            }
        }

    private:
        bool m_could_reserve{false};
    };

    static RPCH scantxoutset() {
        const std::string EXAMPLE_DESCRIPTOR_RAW = "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)#fm24fxxy";

        return RPCH{"scantxoutset",
            "\nScans the unspent transaction output set for entries that match certain output descriptors.\n"
            "Examples of output descriptors are:\n"
            "    addr(<address>)                      Outputs whose scriptPubKey corresponds to the specified address (does not include P2PK)\n"
            "    raw(<hex script>)                    Outputs whose scriptPubKey equals the specified hex scripts\n"
            "    combo(<pubkey>)                      P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH outputs for the given pubkey\n"
            "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
            "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
            "    tr(<pubkey>)                         P2TR\n"
            "    tr(<pubkey>,{pk(<pubkey>)})          P2TR with single fallback pubkey in tapscript\n"
            "    rawtr(<pubkey>)                      P2TR with the specified key as output key rather than inner\n"
            "    wsh(and_v(v:pk(<pubkey>),after(2)))  P2WSH miniscript with mandatory pubkey and a timelock\n"
            "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
            "or more path elements separated by \"/\", and optionally ending in \"/*\" (unhardened), or \"/*'\" or \"/*h\" (hardened) to specify all\n"
            "unhardened or hardened child keys.\n"
            "In the latter case, a range needs to be specified by below if different from 1000.\n"
            "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n",
            {
                scan_action_arg_desc,
                scan_objects_arg_desc,
            },
            {
                RPCResult{"when action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::BOOL, "success", "Whether the scan was completed"},
                    {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs scanned"},
                    {RPCResult::Type::NUM, "height", "The current block height (index)"},
                    {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                    {RPCResult::Type::ARR, "unspents", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                            {RPCResult::Type::NUM, "vout", "The vout value"},
                            {RPCResult::Type::STR_HEX, "scriptPubKey", "The script key"},
                            {RPCResult::Type::STR, "desc", "A specialized descriptor for the matched scriptPubKey"},
                            {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the unspent output"},
                            {RPCResult::Type::BOOL, "coinbase", "Whether this is a coinbase output"},
                            {RPCResult::Type::NUM, "height", "Height of the unspent transaction output"},
                        }},
                    }},
                    {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of all found unspent outputs in " + CURRENCY_UNIT},
                }},
                scan_result_abort,
                scan_result_status_some,
                scan_result_status_none,
            },
            RPCExamples{
                HelpExampleCli("scantxoutset", "start \'[\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]\'") +
                HelpExampleCli("scantxoutset", "status") +
                HelpExampleCli("scantxoutset", "abort") +
                HelpExampleRpc("scantxoutset", "\"start\", [\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]") +
                HelpExampleRpc("scantxoutset", "\"status\"") +
                HelpExampleRpc("scantxoutset", "\"abort\"")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                UniValue result(UniValue::VOBJ);
                if (request.params[0].get_str() == "status") {
                    CoinsViewScanReserver reserver;
                    if (reserver.reserve()) {
                        // No scan in progress
                        return UniValue::VNULL;
                    }
                    result.pushKV("progress", g_scan_progress.load());
                    return result;
                } else if (request.params[0].get_str() == "abort") {
                    CoinsViewScanReserver reserver;
                    if (reserver.reserve()) {
                        // Reserve was possible, which means no scan was running
                        return false;
                    }
                    // Set the abort flag
                    g_should_abort_scan = true;
                    return true;
                } else if (request.params[0].get_str() == "start") {
                    CoinsViewScanReserver reserver;
                    if (!reserver.reserve()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
                    }

                    if (request.params.size() < 2) {
                        throw JSONRPCError(RPC_MISC_ERROR, "scanobjects argument is required for the start action");
                    }

                    std::set<CScript> needles;
                    std::map<CScript, std::string> descriptors;
                    CAmount total_in = 0;

                    // Loop through the scan objects
                    for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
                        FlatSigningProvider provider;
                        auto scripts = EvalDescriptorStringOrObject(scanobject, provider);
                        for (CScript& script : scripts) {
                            std::string inferred = InferDescriptor(script, provider)->ToString();
                            needles.emplace(script);
                            descriptors.emplace(std::move(script), std::move(inferred));
                        }
                    }

                    // Scan the unspent transaction output set for inputs
                    UniValue unspents(UniValue::VARR);
                    std::vector<CTxOut> input_txos;
                    std::map<COutPoint, Coin> coins;
                    g_should_abort_scan = false;
                    int64_t count = 0;
                    std::unique_ptr<CCoinsViewCursor> pcursor;
                    const CBlockIndex* tip;
                    NodeContext& node = EnsureAnyNodeContext(request.context);
                    {
                        ChainstateManager& chainman = EnsureChainman(node);
                        LOCK(cs_main);
                        Chainstate& active_chainstate = chainman.ActiveChainstate();
                        active_chainstate.ForceFlushStateToDisk();
                        pcursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
                        tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
                    }
                    bool res = FindScriptPubKey(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needles, coins, node.rpc_interruption_point);
                    result.pushKV("success", res);
                    result.pushKV("txouts", count);
                    result.pushKV("height", tip->nHeight);
                    result.pushKV("bestblock", tip->GetBlockHash().GetHex());

                    for (const auto& it : coins) {
                        const COutPoint& outpoint = it.first;
                        const Coin& coin = it.second;
                        const CTxOut& txo = coin.out;
                        input_txos.push_back(txo);
                        total_in += txo.nValue;

                        UniValue unspent(UniValue::VOBJ);
                        unspent.pushKV("txid", outpoint.hash.GetHex());
                        unspent.pushKV("vout", (int32_t)outpoint.n);
                        unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
                        unspent.pushKV("desc", descriptors[txo.scriptPubKey]);
                        unspent.pushKV("amount", ValueFromAmount(txo.nValue));
                        unspent.pushKV("coinbase", coin.IsCoinBase());
                        unspent.pushKV("height", (int32_t)coin.nHeight);

                        unspents.push_back(unspent);
                    }
                    result.pushKV("unspents", unspents);
                    result.pushKV("total_amount", ValueFromAmount(total_in));
                } else {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", request.params[0].get_str()));
                }
                return result;
            },
        };
    }

    enum class BlockFilterScanAction { START, ABORT, STATUS };

    struct BlockFilterNeedle {
        std::vector<unsigned char> scriptPubKey;
    };

    class BlockFiltersScanReserver {
    public:
        BlockFiltersScanReserver() {
            if (g_scanfilter_in_progress.exchange(true)) {
                return;
            }
            m_could_reserve = true;
        }

        bool reserve() {
            return m_could_reserve;
        }

        ~BlockFiltersScanReserver() {
            if (m_could_reserve) {
                g_scanfilter_in_progress = false;
            }
        }

    private:
        bool m_could_reserve{false};
    };

    static bool CheckBlockFilterMatches(BlockManager& blockman, const CBlockIndex& blockindex, const std::vector<BlockFilterNeedle>& needles) {
        const CBlock block{GetBlockChecked(blockman, &blockindex)};
        const CBlockUndo block_undo{GetUndoChecked(blockman, &blockindex)};

        // Check if any of the outputs match the scriptPubKey
        for (const auto& tx : block.vtx) {
            if (std::any_of(tx->vout.cbegin(), tx->vout.cend(), [&](const auto& txout) {
                    return std::any_of(needles.cbegin(), needles.cend(), [&](const auto& needle) {
                        return needle.scriptPubKey == std::vector<unsigned char>(txout.scriptPubKey.begin(), txout.scriptPubKey.end());
                    });
                })) {
                return true;
            }
        }

        // Check if any of the inputs match the scriptPubKey
        for (const auto& txundo : block_undo.vtxundo) {
            if (std::any_of(txundo.vprevout.cbegin(), txundo.vprevout.cend(), [&](const auto& coin) {
                    return std::any_of(needles.cbegin(), needles.cend(), [&](const auto& needle) {
                        return needle.scriptPubKey == std::vector<unsigned char>(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end());
                    });
                })) {
                return true;
            }
        }

        return false;
    }

    enum class BlockFilterScanAction { START, ABORT, STATUS };

    struct BlockFilterNeedle {
        std::vector<unsigned char> scriptPubKey;
    };

    class BlockFiltersScanReserver {
    public:
        BlockFiltersScanReserver() {
            if (g_scanfilter_in_progress.exchange(true)) {
                return;
            }
            m_could_reserve = true;
        }

        bool reserve() {
            return m_could_reserve;
        }

        ~BlockFiltersScanReserver() {
            if (m_could_reserve) {
                g_scanfilter_in_progress = false;
            }
        }

    private:
        bool m_could_reserve{false};
    };

    static UniValue HandleScanBlocks(const JSONRPCRequest& request) {
        UniValue result(UniValue::VOBJ);
        BlockFiltersScanReserver reserver;

        if (request.params[0].get_str() == "status") {
            if (reserver.reserve()) {
                return NullUniValue;
            }
            result.pushKV("progress", g_scanfilter_progress.load());
            result.pushKV("current_height", g_scanfilter_progress_height.load());
        } else if (request.params[0].get_str() == "abort") {
            if (reserver.reserve()) {
                return false;
            }
            g_scanfilter_should_abort_scan = true;
            return true;
        } else if (request.params[0].get_str() == "start") {
            if (!reserver.reserve()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
            }

            const std::string filterTypeName = request.params[4].isNull() ? "basic" : request.params[4].get_str();
            BlockFilterType filterType;

            if (!BlockFilterTypeByName(filterTypeName, filterType)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
            }

            UniValue options = request.params[5].isNull() ? UniValue::VOBJ : request.params[5];
            bool filterFalsePositives = options.exists("filter_false_positives") ? options["filter_false_positives"].get_bool() : false;

            BlockFilterIndex* index = GetBlockFilterIndex(filterType);

            if (!index) {
                throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filterTypeName);
            }

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            int startHeight = request.params[2].isNull() ? 0 : request.params[2].getInt<int>();
            int stopHeight = request.params[3].isNull() ? chainman.ActiveChain().Tip()->nHeight : request.params[3].getInt<int>();
            const CBlockIndex* block = chainman.ActiveChain().At(startHeight);
            const CBlockIndex* stopBlock = chainman.ActiveChain().At(stopHeight);

            CHECK_NONFATAL(block);

            GCSFilter::ElementSet needleSet;

            for (const UniValue& scanObject : request.params[1].get_array().getValues()) {
                FlatSigningProvider provider;
                std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanObject, provider);

                for (const CScript& script : scripts) {
                    needleSet.emplace(script.begin(), script.end());
                }
            }

            UniValue blocks(UniValue::VARR);
            const int amountPerChunk = 10000;
            const CBlockIndex* startIndex = block;
            std::vector<BlockFilter> filters;
            const CBlockIndex* startBlock = block;
            const int totalBlocksToProcess = stopBlock->nHeight - startBlock->nHeight;

            g_scanfilter_should_abort_scan = false;
            g_scanfilter_progress = 0;
            g_scanfilter_progress_height = startBlock->nHeight;

            while (block) {
                node.rpc_interruption_point();

                if (g_scanfilter_should_abort_scan) {
                    LogPrintf("scanblocks RPC aborted at height %d.\n", block->nHeight);
                    break;
                }

                const CBlockIndex* next = chainman.ActiveChain().Next(block);

                if (block == stopBlock) {
                    next = nullptr;
                }

                if (startIndex->nHeight + amountPerChunk == block->nHeight || next == nullptr) {
                    LogPrint(BCLog::RPC, "Fetching blockfilters from height %d to height %d.\n", startIndex->nHeight, block->nHeight);

                    if (index->LookupFilterRange(startIndex->nHeight, block, filters)) {
                        for (const BlockFilter& filter : filters) {
                            if (filter.GetFilter().MatchAny(needleSet)) {
                                if (filterFalsePositives) {
                                    const CBlockIndex& blockIndex = *CHECK_NONFATAL(WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(filter.GetBlockHash())));

                                    if (!CheckBlockFilterMatches(chainman.m_blockman, blockIndex, needleSet)) {
                                        continue;
                                    }
                                }

                                blocks.push_back(filter.GetBlockHash().GetHex());
                                LogPrint(BCLog::RPC, "scanblocks: found match in %s\n", filter.GetBlockHash().GetHex());
                            }
                        }
                    }

                    startIndex = block;

                    int blocksProcessed = block->nHeight - startBlock->nHeight;

                    if (totalBlocksToProcess > 0) {
                        g_scanfilter_progress = (int)(100.0 / totalBlocksToProcess * blocksProcessed);
                    } else {
                        g_scanfilter_progress = 100;
                    }

                    g_scanfilter_progress_height = block->nHeight;
                }

                block = next;
            }

            result.pushKV("from_height", startBlock->nHeight);
            result.pushKV("to_height", g_scanfilter_progress_height.load());
            result.pushKV("relevant_blocks", blocks);
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", request.params[0].get_str()));
        }

        return result;
    }

    // Define a struct to represent the scan action arguments.
    struct ScanActionArgs {
        int startHeight{0};
        int stopHeight{-1}; // -1 means "chain tip"
        std::string filterType{BlockFilterTypeName(BlockFilterType::BASIC)};
        bool filterFalsePositives{false};
    };

    // Define a struct to represent the scan result.
    struct ScanResult {
        int fromHeight{0};
        int toHeight{0};
        std::vector<std::string> relevantBlocks;
    };

    // Function to handle the scanblocks action.
    ScanResult HandleScanBlocks(const ScanActionArgs& args) {
        ScanResult result;

        // Your existing logic for scanning blocks goes here...

        return result;
    }

    // Define the scanblocks RPC method.
    static RPCH scanblocks() {
        return RPCH{"scanblocks",
            "\nReturn relevant blockhashes for given descriptors (requires blockfilterindex).\n"
            "This call may take several minutes. Make sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
            {
                scan_action_arg_desc,
                scan_objects_arg_desc,
                RPCArg{"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Height to start to scan from"},
                RPCArg{"stop_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"chain tip"}, "Height to stop to scan"},
                RPCArg{"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
                RPCArg{"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                    {
                        {"filter_false_positives", RPCArg::Type::BOOL, RPCArg::Default{false}, "Filter false positives (slower and may fail on pruned nodes). Otherwise they may occur at a rate of 1/M"},
                    },
                    RPCArgOptions{.oneline_description="\"options\""}},
            },
            {
                scan_result_status_none,
                RPCResult{"When action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "from_height", "The height we started the scan from"},
                    {RPCResult::Type::NUM, "to_height", "The height we ended the scan at"},
                    {RPCResult::Type::ARR, "relevant_blocks", "Blocks that may have matched a scanobject.", {
                        {RPCResult::Type::STR_HEX, "blockhash", "A relevant blockhash"},
                    }},
                }},
                RPCResult{"when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "progress", "Approximate percent complete"},
                    {RPCResult::Type::NUM, "current_height", "Height of the block currently being scanned"},
                }},
                scan_result_abort,
            },
            RPCExamples{
                HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 300000") +
                HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 100 150 basic") +
                HelpExampleCli("scanblocks", "status") +
                HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 300000") +
                HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 100, 150, \"basic\"") +
                HelpExampleRpc("scanblocks", "\"status\"")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                ScanActionArgs args;

                // Extract and validate input parameters from the request.
                // Populate the args struct.

                // Call the HandleScanBlocks function with the args struct.
                ScanResult result = HandleScanBlocks(args);

                // Convert the result to UniValue and return it.
                UniValue ret(UniValue::VOBJ);

                // Populate ret with data from the result struct.

                return ret;
            }
        };
    }

    // Define a struct to represent the getblockfilter action arguments.
    struct GetBlockFilterArgs {
        std::string blockHash;
        std::string filterType{BlockFilterTypeName(BlockFilterType::BASIC)};
    };

    // Function to handle the getblockfilter action.
    UniValue HandleGetBlockFilter(const GetBlockFilterArgs& args, const JSONRPCRequest& request) {
        SPHINXHash::SPHINX_256 blockHash = ParseHashV(args.blockHash, "blockhash");

        BlockFilterType filterType;
        if (!BlockFilterTypeByName(args.filterType, filterType)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
        }

        BlockFilterIndex* index = GetBlockFilterIndex(filterType);
        if (!index) {
            throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + args.filterType);
        }

        const CBlockIndex* blockIndex;
        bool blockWasConnected;

        {
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            blockIndex = chainman.m_blockman.LookupBlockIndex(blockHash);
            if (!blockIndex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
            blockWasConnected = blockIndex->IsValid(BLOCK_VALID_SCRIPTS);
        }

        bool indexReady = index->BlockUntilSyncedToCurrentChain();

        BlockFilter filter;
        SPHINXHash::SPHINX_256 filterHeader;
        
        if (!index->LookupFilter(blockIndex, filter) || !index->LookupFilterHeader(blockIndex, filterHeader)) {
            int errCode;
            std::string errMsg = "Filter not found.";

            if (!blockWasConnected) {
                errCode = RPC_INVALID_ADDRESS_OR_KEY;
                errMsg += " Block was not connected to the active chain.";
            } else if (!indexReady) {
                errCode = RPC_MISC_ERROR;
                errMsg += " Block filters are still in the process of being indexed.";
            } else {
                errCode = RPC_INTERNAL_ERROR;
                errMsg += " This error is unexpected and indicates index corruption.";
            }

            throw JSONRPCError(errCode, errMsg);
        }

        UniValue ret(UniValue::VOBJ);
        ret.pushKV("filter", HexStr(filter.GetEncodedFilter()));
        ret.pushKV("header", HexStr(filterHeader));
        return ret;
    }

    // Define the getblockfilter RPC method.
    static RPCH getblockfilter() {
        return RPCH{"getblockfilter",
            "\nRetrieve a SIP 157 content filter for a particular block.\n",
            {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the block"},
                {"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "filter", "the hex-encoded filter data"},
                    {RPCResult::Type::STR_HEX, "header", "the hex-encoded filter header"},
                }},
            RPCExamples{
                HelpExampleCli("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" \"basic\"") +
                HelpExampleRpc("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\", \"basic\"")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                GetBlockFilterArgs args;

                // Extract and validate input parameters from the request.
                // Populate the args struct.

                // Call the HandleGetBlockFilter function with the args struct.
                UniValue result = HandleGetBlockFilter(args, request);

                return result;
            }
        };
    }

    // Struct to represent UTXO snapshot metadata.
    struct SnapshotMetadata {
        std::string baseHash;
        uint64_t coinsWritten;
        int baseHeight;
        std::string path;
        std::string txOutsetHash;
        uint64_t nChainTx;
    };

    // Function to create a UTXO snapshot.
    SnapshotMetadata CreateUTXOSnapshot(NodeContext& node, Chainstate& chainstate, const fs::path& path, const fs::path& tempPath) {
        std::unique_ptr<CCoinsViewCursor> pcursor;
        std::optional<CCoinsStats> maybeStats;
        const CBlockIndex* tip;

        {
            LOCK(::cs_main);

            chainstate.ForceFlushStateToDisk();

            maybeStats = GetUTXOStats(&chainstate.CoinsDB(), chainstate.m_blockman, CoinStatsHashType::HASH_SERIALIZED, node.rpc_interruption_point);
            if (!maybeStats) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
            }

            pcursor = chainstate.CoinsDB().Cursor();
            tip = CHECK_NONFATAL(chainstate.m_blockman.LookupBlockIndex(maybeStats->hashBlock));
        }

        LOG_TIME_SECONDS(strprintf("Writing UTXO snapshot at height %s (%s) to file %s (via %s)",
            tip->nHeight, tip->GetBlockHash().ToString(),
            fs::PathToString(path), fs::PathToString(tempPath)));

        SnapshotMetadata metadata{
            tip->GetBlockHash().ToString(),
            maybeStats->coins_count,
            tip->nHeight,
            path.u8string(),
            maybeStats->hashSerialized.ToString(),
            uint64_t(tip->nChainTx)
        };

        FILE* file = fsbridge::fopen(tempPath, "wb");
        AutoFile afile(file);

        if (afile.IsNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Couldn't open file " + tempPath.u8string() + " for writing.");
        }

        afile << metadata;

        COutPoint key;
        Coin coin;
        unsigned int iter = 0;

        while (pcursor->Valid()) {
            if (iter % 5000 == 0) node.rpc_interruption_point();
            ++iter;
            if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
                afile << key;
                afile << coin;
            }

            pcursor->Next();
        }

        afile.fclose();
        return metadata;
    }

    // RPC method to serialize the UTXO set to a file.
    static RPCH dumptxoutset() {
        return RPCH{
            "dumptxoutset",
            "Write the serialized UTXO set to disk.",
            {
                {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "Path to the output file. If relative, will be prefixed by datadir."},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_written", "the number of coins written in the snapshot"},
                    {RPCResult::Type::STR_HEX, "base_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was written to"},
                    {RPCResult::Type::STR_HEX, "txoutset_hash", "the hash of the UTXO set contents"},
                    {RPCResult::Type::NUM, "nchaintx", "the number of transactions in the chain up to and including the base block"},
                }
            },
            RPCExamples{
                HelpExampleCli("dumptxoutset", "utxo.dat")
            },
            [&](const RPCH& self, const JSONRPCRequest& request) -> UniValue {
                const ArgsManager& args{EnsureAnyArgsman(request.context)};
                const fs::path path = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str()));
                const fs::path tempPath = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str() + ".incomplete"));

                if (fs::exists(path)) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        path.u8string() + " already exists. If you are sure this is what you want, "
                        "move it out of the way first");
                }

                // Call the CreateUTXOSnapshot function to create the UTXO snapshot.
                SnapshotMetadata result = CreateUTXOSnapshot(
                    EnsureAnyNodeContext(request.context),
                    EnsureAnyChainman(request.context).ActiveChainstate(),
                    afile,
                    path,
                    tempPath);

                result.pushKV("path", path.u8string());
                return result;
            },
        };
    }
    
    // Define a lambda function to register blockchain RPC commands.
    auto RegisterBlockchainRPCCommands = [](CRPCTable& t) {
        static const CRPCCommand commands[]{
            {"blockchain", &getblockchaininfo},
            {"blockchain", &getchaintxstats},
            {"blockchain", &getblockstats},
            {"blockchain", &getbestblockhash},
            {"blockchain", &getblockcount},
            {"blockchain", &getblock},
            {"blockchain", &getblockfrompeer},
            {"blockchain", &getblockhash},
            {"blockchain", &getblockheader},
            {"blockchain", &getchaintips},
            {"blockchain", &getdifficulty},
            {"blockchain", &getdeploymentinfo},
            {"blockchain", &gettxout},
            {"blockchain", &gettxoutsetinfo},
            {"blockchain", &pruneblockchain},
            {"blockchain", &verifychain},
            {"blockchain", &preciousblock},
            {"blockchain", &scantxoutset},
            {"blockchain", &scanblocks},
            {"blockchain", &getblockfilter},
            {"hidden", &invalidateblock},
            {"hidden", &reconsiderblock},
            {"hidden", &waitfornewblock},
            {"hidden", &waitforblock},
            {"hidden", &waitforblockheight},
            {"hidden", &syncwithvalidationinterfacequeue},
            {"hidden", &dumptxoutset},
        };
        for (const auto& c : commands) {
            t.appendCommand(c.name, &c);
        }
    };
} // namespace SPHINXBlockchain