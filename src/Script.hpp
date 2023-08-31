// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#ifndef SCRIPT_H
#define SCRIPT_H

#include <iostream>
#include <string>
#include <vector>
#include <stack>
#include <map>

#include "Utxo.hpp"

enum class Opcode {
    OP_CURVE448_KEYPAIR,
    OP_KYBER1024_KEYPAIR,
    OP_HYBRID_ENCRYPT,
    OP_HYBRID_DECRYPT,
    OP_SIGN_TRANSACTION,
    OP_VERIFY_TRANSACTION,
    OP_CHECK_FUNDS,
    OP_VALIDATE_TRANSACTION,
    OP_FIND_UTXOS_FOR_ADDRESS,
    OP_GET_UTXO,
    OP_GET_TOTAL_UTXO_AMOUNT,
    OP_SPHINX_256 // Add the new opcode for hash operation
};

class ScriptInterpreter {
public:
    bool executeScript(const std::vector<Opcode>& script);

private:
    std::stack<bool> stack;
    Encryption encryption;
    SPHINXPrivKey sphinxPrivateKey;
    std::map<std::string, SPHINXUtxo::UTXO> utxoSet;

    // Declare the opcode execution methods
    void opCurve448Keypair();
    void opKyber1024Keypair();
    void opHybridEncrypt();
    void opHybridDecrypt();
    void opSignTransaction();
    void opVerifyTransaction();
    void opCheckFunds();
    void opValidateTransaction();
    void opFindUTXOsForAddress();
    void opGetUTXO();
    void opGetTotalUTXOAmount();
    void opSPHINX_256(); // Declare the new opcode method
};

