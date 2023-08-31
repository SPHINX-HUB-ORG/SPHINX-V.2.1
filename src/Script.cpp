// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.

#include <iostream>
#include <string>
#include <vector>
#include <stack>
#include <map>

#include "Key.hpp"
#include "Script.hpp"
#include "Sign.hpp"
#include "Utxo.hpp"
#include "Hash.hpp"

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
    OP_GET_TOTAL_UTXO_AMOUNT
};

class ScriptInterpreter {
public:
    bool executeScript(const std::vector<Opcode>& script);

private:
    std::stack<bool> stack;
    Encryption encryption;
    SPHINXPrivKey sphinxPrivateKey;
    std::map<std::string, SPHINXUtxo::UTXO> utxoSet; // Maintain UTXO set here

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
    void opSPHINX_256();
};

bool ScriptInterpreter::executeScript(const std::vector<Opcode>& script) {
    for (const Opcode& opcode : script) {
        switch (opcode) {
            case Opcode::OP_CURVE448_KEYPAIR:
                opCurve448Keypair();
                break;
            case Opcode::OP_KYBER1024_KEYPAIR:
                opKyber1024Keypair();
                break;
            case Opcode::OP_HYBRID_ENCRYPT:
                opHybridEncrypt();
                break;
            case Opcode::OP_HYBRID_DECRYPT:
                opHybridDecrypt();
                break;
            case Opcode::OP_SIGN_TRANSACTION:
                opSignTransaction();
                break;
            case Opcode::OP_VERIFY_TRANSACTION:
                opVerifyTransaction();
                break;
            case Opcode::OP_CHECK_FUNDS:
                opCheckFunds();
                break;
            case Opcode::OP_VALIDATE_TRANSACTION:
                opValidateTransaction();
                break;
            case Opcode::OP_FIND_UTXOS_FOR_ADDRESS:
                opFindUTXOsForAddress();
                break;
            case Opcode::OP_GET_UTXO:
                opGetUTXO();
                break;
            case Opcode::OP_GET_TOTAL_UTXO_AMOUNT:
                opGetTotalUTXOAmount();
                break;
            case Opcode::OP_SPHINX_256: // Handle the new opcode for hashing
                opSPHINX_256();
                break;
            // Add case statements for other opcodes
        }
    }

    if (stack.size() != 1) {
        return false;
    }

    return stack.top();
}

void ScriptInterpreter::opSignTransaction() {
    std::string transactionData = /* Get the transaction data from the stack */;
    
    // Sign the transaction data using the SPHINX private key
    std::string signature = SPHINXSign::signTransactionData(transactionData, sphinxPrivateKey);

    stack.push(true); // Pushing true to indicate success
}

void ScriptInterpreter::opVerifyTransaction() {
    std::string signedTransaction = /* Get the signed transaction from the stack */;

    // Extract the public key and signature from the signed transaction
    SPHINXPubKey publicKey = SPHINXSign::extractPublicKey(signedTransaction);
    std::string signature = /* Extract the signature from the signed transaction */;

    // Verify the signature using the public key and the extracted signature
    bool isSignatureValid = SPHINXSign::verify_data(signedTransaction.data(), signature, publicKey);

    stack.push(isSignatureValid);
}

void ScriptInterpreter::opSPHINX_256() {
    std::string data = /* Get the data from the stack */;

    // Calculate the hash using SPHINX_256 hash function
    std::string hashResult = SPHINXHash::calculateHash(data, SPHINXHash::SPHINX_256);

    // Push the hash result onto the stack or perform desired actions
    // For example, you can push the hash onto the stack like this:
    stack.push(hashResult);
}