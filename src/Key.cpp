// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


#include <string>
#include <vector>
#include <cstring>
#include <utility>
#include <iostream>
#include <algorithm>
#include <cstdint>

#include "Hybrid_key.hpp"
#include "Hash.hpp"
#include "Key.hpp"
#include "base58check.hpp"
#include "base58.hpp"
#include "hash/Ripmed160.hpp"


namespace SPHINXHybridKey {
    // Assume the definition of SPHINXHybridKey
    struct HybridKeypair {};
}

namespace SPHINXHash {
    // Assume the definition of SPHINX_256 function
    std::string SPHINX_256(const std::vector<unsigned char>& data) {
        // Dummy implementation for demonstration purposes
        return "hashed_" + std::string(data.begin(), data.end());
    }

    // Assume the definition of RIPEMD-160 function
    std::string RIPEMD_160(const std::vector<unsigned char>& data) {
        // Dummy implementation for demonstration purposes
        return "ripemd160_" + std::string(data.begin(), data.end());
    }
}

// Base58 characters (excluding confusing characters: 0, O, I, l) for human readability
static const std::string base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function to encode data using Base58
std::string EncodeBase58(const std::vector<unsigned char>& data) {
    // Count leading zeros
    size_t zeros_count = 0;
    for (const unsigned char byte : data) {
        if (byte != 0) {
            break;
        }
        ++zeros_count;
    }

    // Convert the data to a big-endian number
    uint64_t num = 0;
    for (size_t i = zeros_count; i < data.size(); ++i) {
        num = num * 256 + data[i];
    }

    // Calculate the necessary length for the encoded string
    size_t encoded_length = (data.size() - zeros_count) * 138 / 100 + 1;
    std::string encoded(encoded_length, '1');

    // Encode the big-endian number in Base58
    for (size_t i = 0; num > 0; ++i) {
        const uint64_t remainder = num % 58;
        num /= 58;
        encoded[encoded_length - i - 1] = base58_chars[remainder];
    }

    return encoded;
}

namespace SPHINXKey {
// Constants
    constexpr size_t CURVE448_PRIVATE_KEY_SIZE = 56;
    constexpr size_t CURVE448_PUBLIC_KEY_SIZE = 56;
    constexpr size_t KYBER1024_PUBLIC_KEY_LENGTH = 800;

    // Define an alias for the public key as SPHINXPubKey
    using SPHINXPubKey = std::vector<unsigned char>;

    // Define an alias for the private key as SPHINXPrivKey
    using SPHINXPrivKey = std::vector<unsigned char>;

    // Function to calculate the SPHINX public key from the private key
    SPHINXPubKey calculatePublicKey(const SPHINXPrivKey& privateKey) {
        // Calculate the SPHINX public key using the provided private key
        SPHINXPubKey sphinxPubKey(privateKey.begin() + CURVE448_PRIVATE_KEY_SIZE, privateKey.end());
        return sphinxPubKey;
    }

    // Function to convert SPHINXKey to string
    std::string sphinxKeyToString(const SPHINXKey& key) {
        return std::string(key.begin(), key.end());
    }

    // Function to generate the smart contract address based on the public key and contract name
    std::string generateAddress(const SPHINXPubKey& publicKey, const std::string& contractName) {
        // Step 1: Convert the public key to a string
        std::string pubKeyString = sphinxKeyToString(publicKey);

        // Step 2: Perform the SPHINX_256 hash on the public key (assuming it returns a std::string)
        std::string sphinxHash = SPHINXHash::SPHINX_256(pubKeyString);

        // Step 3: Perform the RIPEMD-160 hash on the SPHINX_256 hash (assuming it returns a std::string)
        std::string ripemd160Hash = SPHINXHash::RIPEMD_160(sphinxHash);

        // Step 4: Add a version byte to the RIPEMD-160 hash (optional)
        // For Bitcoin addresses, the version byte is 0x00 (mainnet). We can change it if needed.
        unsigned char versionByte = 0x00;
        std::string dataWithVersion(1, versionByte);
        dataWithVersion += ripemd160Hash;

        // Step 5: Calculate the checksum (first 4 bytes of double SPHINX_256 hash)
        std::string checksum = SPHINXHash::SPHINX_256(SPHINXHash::SPHINX_256(dataWithVersion)).substr(0, 4);

        // Step 6: Concatenate the data with the checksum
        std::string dataWithChecksum = dataWithVersion + checksum;

        // Step 7: Perform Base58Check encoding
        std::string address = EncodeBase58(reinterpret_cast<const unsigned char*>(dataWithChecksum.data()),
                                           dataWithChecksum.size());

        return address;
    }

    // Function to generate the hybrid key pair
    SPHINXHybridKey::HybridKeypair generateHybridKeypair() {
        // Generate Curve448 key pair
        SPHINXKey::SPHINXPrivKey curve448PrivateKey = generateCurve448PrivateKey();
        SPHINXKey::SPHINXPubKey curve448PublicKey = generateCurve448PublicKey();

        // Generate Kyber1024 key pair
        SPHINXKey::SPHINXPrivKey kyberPrivateKey = generateKyberPrivateKey();
        SPHINXKey::SPHINXPubKey kyberPublicKey = generateKyberPublicKey();

        // Create the hybrid key pair structure
        SPHINXHybridKey::HybridKeypair hybridKeyPair;
        hybridKeyPair.curve448_private_key = curve448PrivateKey;
        hybridKeyPair.curve448_public_key = curve448PublicKey;
        hybridKeyPair.kyber_private_key = kyberPrivateKey;
        hybridKeyPair.kyber_public_key = kyberPublicKey;

        return hybridKeyPair;
    }

    // Function to generate and perform key exchange using the hybrid method
    SPHINXHybridKey::HybridKeypair generateAndPerformKeyExchange() {
        // Generate Curve448 key pair
        SPHINXKey::SPHINXPrivKey curve448PrivateKey = SPHINXHybridKey::generateCurve448PrivateKey();
        SPHINXKey::SPHINXPubKey curve448PublicKey = SPHINXHybridKey::generateCurve448PublicKey();

        // Generate Kyber1024 key pair
        SPHINXKey::SPHINXPrivKey kyberPrivateKey = SPHINXHybridKey::generateKyberPrivateKey();
        SPHINXKey::SPHINXPubKey kyberPublicKey = SPHINXHybridKey::generateKyberPublicKey();

        // Create the hybrid key pair structure
        SPHINXHybridKey::HybridKeypair hybridKeyPair;
        hybridKeyPair.curve448_private_key = curve448PrivateKey;
        hybridKeyPair.curve448_public_key = curve448PublicKey;
        hybridKeyPair.kyber_private_key = kyberPrivateKey;
        hybridKeyPair.kyber_public_key = kyberPublicKey;

        return hybridKeyPair;
    }

    // Function to generate and perform key exchange using the hybrid method
    void generate_and_perform_key_exchange() {
        // Generate Curve448 key pair
        SPHINXKey::SPHINXPrivKey curve448PrivateKey = generateCurve448PrivateKey();
        SPHINXKey::SPHINXPubKey curve448PublicKey = generateCurve448PublicKey();

        // Generate Kyber1024 key pair
        SPHINXKey::SPHINXPrivKey kyberPrivateKey = generateKyberPrivateKey();
        SPHINXKey::SPHINXPubKey kyberPublicKey = generateKyberPublicKey();

        // Perform the key exchange using X448 and Kyber1024 KEM
        std::vector<uint8_t> encapsulated_key;
        std::string shared_secret = SPHINXHybridKey::encapsulateHybridSharedSecret(curve448PrivateKey, kyberPrivateKey, encapsulated_key);

        // Decapsulate the shared secret using Kyber1024 KEM
        std::string decapsulated_shared_secret = SPHINXHybridKey::decapsulateHybridSharedSecret(curve448PrivateKey, kyberPrivateKey, encapsulated_key);

        // Check if the decapsulated shared secret matches the original shared secret
        if (decapsulated_shared_secret == shared_secret) {
            std::cout << "Decapsulation successful. Shared secrets match." << std::endl;
        } else {
            std::cout << "Decapsulation failed. Shared secrets do not match." << std::endl;
        }

        // Example message to be encrypted
        std::string message = "Hello, this is a secret message.";

        // Encrypt the message using Kyber1024 PKE with the public key
        std::string encrypted_message = SPHINXHybridKey::encryptMessage(message, kyberPublicKey);

        // Decrypt the message using Kyber1024 PKE with the private key
        std::string decrypted_message = SPHINXHybridKey::decryptMessage(encrypted_message, kyberPrivateKey);

        // Print the original message, encrypted message, and decrypted message
        std::cout << "Original Message: " << message << std::endl;
        std::cout << "Encrypted Message: " << encrypted_message << std::endl;
        std::cout << "Decrypted Message: " << decrypted_message << std::endl;

        return shared_secret;
    }

    // Function to print the generated keys and return them as strings
    std::pair<std::string, std::string> printKeyPair(const std::string& name, const SPHINXKey::SPHINXPrivKey& privateKey, const SPHINXKey::SPHINXPubKey& publicKey) {
        // Convert private key to string
        std::string privKeyString = sphinxKeyToString(privateKey);
        // Convert public key to string
        std::string pubKeyString = sphinxKeyToString(publicKey);

        // Print the private and public keys
        std::cout << name << " private key: " << privKeyString << std::endl;
        std::cout << name << " public key: " << pubKeyString << std::endl;

        // Generate and print the contract address
        std::string contractName = "MyContract";
        std::string contractAddress = generateAddress(publicKey, contractName);
        std::cout << "Contract Address: " << contractAddress << std::endl;

        // Return the keys and contract address as strings
        return std::make_pair(privKeyString, pubKeyString);
    }
} // namespace SPHINXKey


// Usage
int main() {
    // Generate hybrid key pair
    SPHINXHybridKey::HybridKeypair hybridKeyPair = SPHINXKey::generate_hybrid_keypair();

    // Print the hybrid key pair details
    std::pair<std::string, std::string> keyStrings = SPHINXKey::printKeyPair("Hybrid", hybridKeyPair.curve448_private_key, hybridKeyPair.kyber_public_key);

    // Perform key exchange and encryption using the hybrid method
    SPHINXKey::generate_and_perform_key_exchange();

    // Example message to be encrypted
    std::string message = "Hello, this is a secret message.";

    // Encrypt the message using Kyber1024 PKE with the hybrid key's public key
    std::string encrypted_message = SPHINXKey::encryptMessage(message, hybridKeyPair.kyber_public_key);

    // Decrypt the message using Kyber1024 PKE with the hybrid key's private key
    std::string decrypted_message = SPHINXKey::decryptMessage(encrypted_message, hybridKeyPair.kyber_private_key);

    // Print the encrypted and decrypted messages
    std::cout << "Original Message: " << message << std::endl;
    std::cout << "Encrypted Message: " << encrypted_message << std::endl;
    std::cout << "Decrypted Message: " << decrypted_message << std::endl;

    return 0;
}
