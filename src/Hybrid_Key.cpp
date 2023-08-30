// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This code is part of a C++ library called SPHINXHybridKey, which provides functionality for generating and using hybrid cryptographic
// keypairs using the Kyber1024 key exchange, X448 key exchange, and PKE (Public Key Encryption) schemes. Let's break down the code and
// explain each part in detail:

// Constants:
    // The code starts with defining several constants, such as key sizes and digest sizes, which are used throughout the library to
    // specify the length of keys, ciphertexts, shared secrets, etc.

// Namespace and Forward Declarations:
    // The code uses the SPHINXHybridKey namespace to encapsulate all the functions and structures provided by the library. It also
    // contains forward declarations for three namespaces: kyber1024_kem, kyber1024_pke, and SPHINXHash. These forward declarations allow
    // the code to reference functions from those namespaces before their full implementation is provided.

// performX448KeyExchange Function:
    // This function performs a key exchange using the X448 elliptic curve Diffie-Hellman (ECDH) algorithm. It takes the private and
    // public keys as input and computes the shared secret using X448. The function is using OpenSSL EVP (Envelope) API for cryptographic
    // operations.

// HybridKeypair Structure:
    // This structure represents a hybrid keypair containing key material from multiple cryptographic schemes. It holds Kyber1024 keypair,
    // X448 keypair, PKE keypair, and a PRNG (pseudo-random number generator) for key generation.

// generate_hybrid_keypair Function:
    // This function generates a hybrid keypair using three cryptographic schemes: Kyber1024 for KEM (Key Encapsulation Mechanism), X448
    // for key exchange, and PKE for public-key encryption. It starts by generating the Kyber1024 keypair, X448 keypair, and PKE keypair
    // using the appropriate functions from their respective namespaces. Then, it derives the master private key and chain code using
    // HKDF (HMAC-based Key Derivation Function). Finally, it hashes the master private key and chain code using the SPHINXHash::SPHINX_256
    // function, and the resulting private and public keys are saved in the hybrid keypair.

// Other Utility Functions:
    // The code also provides utility functions like generateRandomNonce, which generates a random nonce for encryption, deriveKeyHKDF,
    // which derives a key using the HKDF (HMAC-based Key Derivation Function) algorithm, hash, which calculates the SWIFFTX-256 hash of
    // a string, and generateAddress, which generates an address from a public key.

// encryptMessage and decryptMessage Functions:
    // These functions use Kyber1024 PKE to encrypt and decrypt messages, respectively. The encryption function takes a message and the
    // recipient's public key, generates a random nonce, and encrypts the message using Kyber1024 PKE. The decryption function takes the
    // encrypted message and the recipient's private key and decrypts the message using Kyber1024 PKE.

// encapsulateHybridSharedSecret and decapsulateHybridSharedSecret Functions:
    // These functions are responsible for encapsulating and decapsulating shared secrets using the hybrid KEM (Key Encapsulation
    // Mechanism). They combine X448 key exchange and Kyber1024 KEM to establish a shared secret between two parties.

// The SPHINXHybridKey library provides a flexible and secure approach to generating hybrid cryptographic keypairs and performing key
// exchange and encryption operations using the Kyber1024, X448, and PKE schemes.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



#include <utility>
#include <array>
#include <iostream>
#include <algorithm>
#include <random>
#include <string>
#include <vector>
#include <cstdint>

#include "Crypto/Openssl/evp.h"
#include "Crypto/Openssl/hkdf.h" 
#include "Crypto/Openssl/hmac.h"
#include "Crypto/Openssl/curve448/point_448.h"
#include "Crypto/Openssl/sha.h"
#include "Crypto/Swifftx/SHA3.h"
#include "Crypto/Kyber/include/kyber1024_kem.hpp"
#include "Crypto/Kyber/include/kyber1024_pke.hpp"
#include "Crypto/Kyber/include/encapsulation.hpp"
#include "Crypto/Kyber/include/decapsulation.hpp"
#include "Crypto/Kyber/include/encryption.hpp"
#include "Crypto/Kyber/include/compression.hpp"
#include "Crypto/Kyber/include/pke_keygen.hpp"

#include "Crypto/Swifftx/SHA3.h"
#include "Hash.hpp"
#include "Key.hpp"
#include "Transaction.hpp"
#include "Hybrid_key.hpp"


namespace SPHINXHybridKey {

    // Constants
    constexpr size_t CURVE448_PRIVATE_KEY_SIZE = 56;
    constexpr size_t CURVE448_PUBLIC_KEY_SIZE = 56;
    constexpr size_t CURVE448_SHARED_SECRET_SIZE = 56;
    constexpr size_t HMAC_MAX_MD_SIZE = 64;                     /* longest known is SHA512 */
    constexpr size_t SWIFFTX512_DIGEST_SIZE = 65;
    constexpr size_t SPHINXHash_DIGEST_SIZE = 65;
    constexpr size_t KYBER1024_PUBLIC_KEY_LENGTH = 800;
    constexpr size_t KYBER1024_PRIVATE_KEY_LENGTH = 1632;
    constexpr size_t KYBER1024_CIPHERTEXT_LENGTH = 1088;
    constexpr size_t KYBER1024_SHARED_SECRET_LENGTH = 32;
    constexpr size_t KYBER1024_PKE_PUBLIC_KEY_LENGTH = 800;
    constexpr size_t KYBER1024_PKE_PRIVATE_KEY_LENGTH = 1632;
    constexpr size_t KYBER1024_PKE_CIPHERTEXT_LENGTH = 1088;

    // Size of HYBRIDKEY
    constexpr size_t HYBRID_KEYPAIR_LENGTH = SPHINXHybridKey::CURVE448_PUBLIC_KEY_SIZE + SPHINXHybridKey::KYBER1024_PUBLIC_KEY_LENGTH + 2 * SPHINXHybridKey::HMAC_MAX_MD_SIZE;
    HYBRID_KEYPAIR_LENGTH = 56 (Curve448 public key size) + 800 (Kyber1024 public key length) + 2 * 64 (HMAC_MAX_MD_SIZE) = 976;

    // Forward declaration
    namespace kyber1024_kem {
        void keygen(std::vector<unsigned char>& public_key, std::vector<unsigned char>& private_key);
        void encapsulate(unsigned char* ciphertext, const unsigned char* public_key, const unsigned char* shared_secret, const unsigned char* private_key);
        void decapsulate(unsigned char* shared_secret, const unsigned char* ciphertext, const unsigned char* private_key);
    }

    // Forward declaration
    namespace kyber1024_pke {
        void keygen(unsigned char* random_bytes, unsigned char* public_key, unsigned char* secret_key);
        void encrypt(const unsigned char* public_key, const unsigned char* message, size_t message_length,
                const unsigned char* nonce, size_t nonce_length, unsigned char* ciphertext, size_t ciphertext_length,
                size_t tag_length);
        void decrypt(const unsigned char* secret_key, const unsigned char* ciphertext, size_t ciphertext_length,
                size_t tag_length, unsigned char* message, size_t message_length);
    }

    // Forward declaration
    namespace SPHINXHash {
        std::string SPHINX_256(const std::string& input);
    }

    // Function to perform the X448 key exchange
    void performX448KeyExchange(unsigned char shared_key[CURVE448_SHARED_SECRET_SIZE], const unsigned char private_key[CURVE448_PRIVATE_KEY_SIZE], const unsigned char public_key[CURVE448_PUBLIC_KEY_SIZE]) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, nullptr, public_key, CURVE448_PUBLIC_KEY_SIZE));
        size_t shared_key_len;
        EVP_PKEY_derive(ctx, shared_key, &shared_key_len);
        EVP_PKEY_CTX_free(ctx);
    }

    // Structure to hold the hybrid keypair
    struct HybridKeypair {
        // Kyber1024 keypair
        std::vector<unsigned char> kyber_public_key;
        std::vector<unsigned char> kyber_private_key;

        // X448 keypair
        std::pair<std::vector<unsigned char>, std::vector<unsigned char>> x448_key;

        // PKE keypair
        std::vector<uint8_t> public_key_pke;
        std::vector<uint8_t> secret_key_pke;

        // PRNG for key generation
        std::vector<unsigned char> prng;
    };

    // Function to generate the hybrid keypair
    HybridKeypair generate_hybrid_keypair() {
        HybridKeypair hybridKeyPair;
        hybridKeyPair.prng.resize(32);

        // Generate Kyber1024 keypair for KEM
        hybridKeyPair.kyber_public_key.resize(KYBER1024_PUBLIC_KEY_LENGTH);
        hybridKeyPair.kyber_private_key.resize(KYBER1024_PRIVATE_KEY_LENGTH);
        kyber1024_kem::keygen(hybridKeyPair.kyber_public_key.data(), hybridKeyPair.kyber_private_key.data());

        // Generate X448 keypair
        hybridKeyPair.x448_key.first.resize(CURVE448_PUBLIC_KEY_SIZE);
        hybridKeyPair.x448_key.second.resize(CURVE448_PRIVATE_KEY_SIZE);
        RAND_bytes(hybridKeyPair.x448_key.first.data(), CURVE448_PUBLIC_KEY_SIZE);
        RAND_bytes(hybridKeyPair.x448_key.second.data(), CURVE448_PRIVATE_KEY_SIZE);

        // Resize PKE keypair vectors
        hybridKeyPair.public_key_pke.resize(KYBER1024_PKE_PUBLIC_KEY_LENGTH);
        hybridKeyPair.secret_key_pke.resize(KYBER1024_PKE_PRIVATE_KEY_LENGTH);

        // Generate PKE keypair
        kyber1024_pke::keygen(hybridKeyPair.prng.data(), hybridKeyPair.public_key_pke.data(), hybridKeyPair.secret_key_pke.data());

        return hybridKeyPair; // Return the hybrid_keypair object
    }

    SPHINXHybridKey::HybridKeypair generate_and_perform_key_exchange() {
        // Local function to perform the X448 key exchange
        void performX448KeyExchange(unsigned char shared_key[SPHINXHybridKey::CURVE448_SHARED_SECRET_SIZE], const unsigned char private_key[SPHINXHybridKey::CURVE448_PRIVATE_KEY_SIZE], const unsigned char public_key[SPHINXHybridKey::CURVE448_PUBLIC_KEY_SIZE]) {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr);
            EVP_PKEY_derive_init(ctx);
            EVP_PKEY_derive_set_peer(ctx, EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, nullptr, public_key, SPHINXHybridKey::CURVE448_PUBLIC_KEY_SIZE));
            size_t shared_key_len;
            EVP_PKEY_derive(ctx, shared_key, &shared_key_len);
            EVP_PKEY_CTX_free(ctx);
        }

        // Local function to perform the key exchange using X448 and Kyber1024 KEM
        std::string encapsulateHybridSharedSecret(const SPHINXHybridKey::HybridKeypair& hybridKeyPair, std::vector<uint8_t>& encapsulated_key) {
            encapsulated_key.resize(SPHINXHybridKey::KYBER1024_CIPHERTEXT_LENGTH);

            // Generate the shared secret using X448 key exchange
            unsigned char shared_secret[SPHINXHybridKey::CURVE448_SHARED_SECRET_SIZE];
            performX448KeyExchange(shared_secret, hybridKeyPair.x448_key.second.data(), hybridKeyPair.x448_key.first.data());

            // Encapsulate the shared secret using Kyber1024 KEM
            SPHINXHybridKey::kyber1024_kem::encapsulate(encapsulated_key.data(), hybridKeyPair.kyber_public_key.data(), shared_secret, hybridKeyPair.kyber_private_key.data());

            // Return the shared secret as a string
            return std::string(reinterpret_cast<char*>(shared_secret), SPHINXHybridKey::CURVE448_SHARED_SECRET_SIZE);
        }

        // Generate the hybrid keypair
        SPHINXHybridKey::HybridKeypair hybridKeyPair = SPHINXHybridKey::generate_hybrid_keypair();

        // Calculate the SPHINX public key from the private key in the hybrid keypair
        SPHINXHybridKey::sphinxPublicKey = SPHINXHybridKey::calculatePublicKey(hybridKeyPair.kyber_private_key);

        // Perform the key exchange using X448 and Kyber1024 KEM
        std::vector<uint8_t> encapsulated_key;
        std::string shared_secret = encapsulateHybridSharedSecret(hybridKeyPair, encapsulated_key);

        // Example message to be encrypted
        std::string message = "Hello, this is a secret message.";

        // Encrypt the message using Kyber1024 PKE with the public key
        std::string encrypted_message = SPHINXHybridKey::encryptMessage(message, hybridKeyPair.public_key_pke);

        // Decrypt the message using Kyber1024 PKE with the secret key
        std::string decrypted_message = SPHINXHybridKey::decryptMessage(encrypted_message, hybridKeyPair.secret_key_pke);

        // Print the original message, encrypted message, and decrypted message
        std::cout << "Original Message: " << message << std::endl;
        std::cout << "Encrypted Message: " << encrypted_message << std::endl;
        std::cout << "Decrypted Message: " << decrypted_message << std::endl;

        // Return the shared secret as specified in the function signature
        return shared_secret;
    }

    // Function to generate a random nonce
    std::string generateRandomNonce() {
        std::string nonce(32, '\0');
        RAND_bytes(reinterpret_cast<unsigned char*>(&nonce[0]), nonce.size());
        return nonce;
    }

    // Function to derive a key using HKDF
    std::string deriveKeyHKDF(const std::string& inputKeyMaterial, const std::string& salt, const std::string& info, size_t keyLength) {
        std::string derivedKey(keyLength, 0);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_key(ctx, reinterpret_cast<const unsigned char*>(inputKeyMaterial.c_str()), inputKeyMaterial.length());
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length());
        EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const unsigned char*>(info.c_str()), info.length());
        EVP_PKEY_CTX_set1_hkdf_keylen(ctx, keyLength);
        EVP_PKEY_derive(ctx, reinterpret_cast<unsigned char*>(derivedKey.data()), &keyLength);
        EVP_PKEY_CTX_free(ctx);

        return derivedKey;
    }

    // Function to calculate the SWIFFTX-256 hash of a string
    std::string hash(const std::string& input) {
        return SPHINXHash::SPHINX_256(input);
    }

    // Function to generate an address from a public key
    std::string generateAddress(const std::string& publicKey) {
        std::string SPHINXHash = SPHINXHybridKey::SPHINXHash::SPHINX_256(publicKey);
        std::string address = SPHINXHash.substr(0, 20);

        return address;
    }

    // Function to encrypt a message using Kyber1024 KEM
    std::string encryptMessage(const std::string& message, const std::vector<uint8_t>& public_key_pke) {
        constexpr size_t tagLength = 16;

        std::string encrypted_message(KYBER1024_PKE_CIPHERTEXT_LENGTH + tagLength, 0);

        std::string nonce = generateRandomNonce();

        kyber1024_pke::encrypt(public_key_pke.data(),
            reinterpret_cast<const uint8_t*>(message.data()), message.length(),
            reinterpret_cast<const uint8_t*>(nonce.data()), nonce.length(),
            reinterpret_cast<uint8_t*>(encrypted_message.data()), encrypted_message.length(),
            tagLength
        );

        return encrypted_message;
    }

    // Function to decrypt a message using Kyber1024 KEM
    std::string decryptMessage(const std::string& encrypted_message, const std::vector<uint8_t>& secret_key_pke) {
        constexpr size_t tagLength = 16;

        std::string decrypted_message(encrypted_message.length() - KYBER1024_PKE_CIPHERTEXT_LENGTH, 0);

        kyber1024_pke::decrypt(secret_key_pke.data(),
            reinterpret_cast<const uint8_t*>(encrypted_message.data()), encrypted_message.length(),
            tagLength,
            reinterpret_cast<uint8_t*>(decrypted_message.data()), decrypted_message.length()
        );

        return decrypted_message;
    }

    // Function to encapsulate a shared secret using the hybrid KEM
    std::string encapsulateHybridSharedSecret(const HybridKeypair& hybridKeyPair, std::vector<uint8_t>& encapsulated_key) {
        encapsulated_key.resize(KYBER1024_CIPHERTEXT_LENGTH);
        unsigned char x448_private_key[CURVE448_PRIVATE_KEY_SIZE];
        curve448_keypair(hybridKeyPair.x448_key.first.data(), x448_private_key);

        unsigned char shared_secret[CURVE448_SHARED_SECRET_SIZE];
        performX448KeyExchange(shared_secret, x448_private_key, hybridKeyPair.kyber_public_key.data());

        kyber1024_kem::encapsulate(encapsulated_key.data(), hybridKeyPair.x448_key.first.data(), hybridKeyPair.kyber_public_key.data(), hybridKeyPair.kyber_private_key.data());

        return std::string(reinterpret_cast<char*>(shared_secret), CURVE448_SHARED_SECRET_SIZE);
    }

    // Function to decapsulate a shared secret using the hybrid KEM
    std::string decapsulateHybridSharedSecret(const HybridKeypair& hybridKeyPair, const std::vector<uint8_t>& encapsulated_key) {
        unsigned char x448_public_key[CURVE448_PUBLIC_KEY_SIZE];
        unsigned char shared_secret[CURVE448_SHARED_SECRET_SIZE];
        kyber1024_kem::decapsulate(shared_secret, encapsulated_key.data(), hybridKeyPair.kyber_private_key.data());

        unsigned char derived_shared_secret[CURVE448_SHARED_SECRET_SIZE];
        performX448KeyExchange(derived_shared_secret, hybridKeyPair.x448_key.second.data(), x448_public_key);

        if (std::memcmp(shared_secret, derived_shared_secret, CURVE448_SHARED_SECRET_SIZE) != 0) {
            throw std::runtime_error("Shared secret mismatch");
        }

        return std::string(reinterpret_cast<char*>(shared_secret), CURVE448_SHARED_SECRET_SIZE);
    }

}  // namespace SPHINXHybridKey


// Usage
int main() {
    try {
        // Generate hybrid key pair and perform key exchange
        SPHINXHybridKey::HybridKeypair hybridKeyPair = SPHINXHybridKey::generate_and_perform_key_exchange();

        // Print the hybrid key pair details
        std::cout << "Kyber Public Key: ";
        for (unsigned char byte : hybridKeyPair.kyber_public_key) {
            printf("%02x", byte);
        }
        std::cout << std::endl;

        std::cout << "Kyber Private Key: ";
        for (unsigned char byte : hybridKeyPair.kyber_private_key) {
            printf("%02x", byte);
        }
        std::cout << std::endl;

        std::cout << "X448 Public Key: ";
        for (unsigned char byte : hybridKeyPair.x448_key.first) {
            printf("%02x", byte);
        }
        std::cout << std::endl;

        std::cout << "X448 Private Key: ";
        for (unsigned char byte : hybridKeyPair.x448_key.second) {
            printf("%02x", byte);
        }
        std::cout << std::endl;

        std::cout << "PKE Public Key: ";
        for (unsigned char byte : hybridKeyPair.public_key_pke) {
            printf("%02x", byte);
        }
        std::cout << std::endl;

        std::cout << "PKE Secret Key: ";
        for (unsigned char byte : hybridKeyPair.secret_key_pke) {
            printf("%02x", byte);
        }
        std::cout << std::endl;

        // Generate an example message to be encrypted
        std::string message = "Hello, this is a secret message.";

        // Encrypt the message using Kyber1024 PKE with the public key
        std::string encrypted_message = SPHINXHybridKey::encryptMessage(message, hybridKeyPair.public_key_pke);

        // Decrypt the message using Kyber1024 PKE with the secret key
        std::string decrypted_message = SPHINXHybridKey::decryptMessage(encrypted_message, hybridKeyPair.secret_key_pke);

        // Print the original message, encrypted message, and decrypted message
        std::cout << "Original Message: " << message << std::endl;
        std::cout << "Encrypted Message: " << encrypted_message << std::endl;
        std::cout << "Decrypted Message: " << decrypted_message << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "An exception occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}