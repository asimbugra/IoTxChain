#ifndef IoTxChain_LIB_H
#define IoTxChain_LIB_H

#include <Arduino.h>
#include <vector>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <vector>
#include <mbedtls/sha256.h>

// rweather/arduinolibs: Ed25519, SHA512 implementations
#include <Ed25519.h>
#include <SHA512.h>

// mbedTLS base64 encoding/decoding
#include <mbedtls/base64.h>

// Custom Base58 encode/decode functions
#include "base58.h"

std::vector<uint8_t> base58ToPubkey(const String& base58Str);

struct EpochInfo {
    uint64_t absoluteSlot;
    uint64_t blockHeight;
    uint64_t epoch;
    uint64_t slotIndex;
    uint64_t slotsInEpoch;
};

// 1) Solana Blockchain Library
struct Pubkey {
    std::vector<uint8_t> data;

    /**
     * @brief Decodes a Base58 string into a Pubkey structure.
     * @param str The Base58 encoded string representing the public key.
     * @return A Pubkey instance containing the decoded 32-byte key.
     */
    static Pubkey fromBase58(const String& str);
};

struct Keypair {
    Pubkey pubkey_;
    std::vector<uint8_t> privkey;

    /**
     * @brief Constructs a Keypair from a 64-byte Ed25519 private key.
     * @param key64 Pointer to the 64-byte private key array.
     * @return A Keypair containing both public and private keys.
     */
    static Keypair fromPrivateKey(const uint8_t* key64);

    /**
     * @brief Returns the public key reference of the keypair.
     * @return Reference to the public key stored in the keypair.
     */
    const Pubkey& pubkey() const;
};

struct AccountMeta {
    Pubkey pubkey;
    bool isSigner;
    bool isWritable;

    /**
     * @brief Constructs an AccountMeta marking the account as a signer.
     * @param key The public key to associate.
     * @return An AccountMeta instance with isSigner=true, isWritable=false.
     */
    static AccountMeta signer(const Pubkey& key);

    /**
     * @brief Constructs an AccountMeta marking the account as writable.
     * @param key The public key to associate.
     * @param isSigner Whether the account is also a signer.
     * @return An AccountMeta instance with isWritable=true.
     */
    static AccountMeta writable(const Pubkey& key, bool isSigner);
};

struct Instruction {
    Pubkey programId;
    std::vector<AccountMeta> accounts;
    std::vector<uint8_t> data;

    /**
     * @brief Constructs a transaction instruction for Solana.
     * @param pid Program ID to be called by this instruction.
     * @param accts List of involved accounts and their access permissions.
     * @param d The instruction data payload.
     */
    Instruction(const Pubkey& pid, const std::vector<AccountMeta>& accts, const std::vector<uint8_t>& d);
};

struct Transaction {
    String recent_blockhash;
    Pubkey fee_payer;
    std::vector<Instruction> instructions;
    std::vector<uint8_t> signature;

    /**
     * @brief Adds an instruction to the transaction.
     * @param ix The instruction to append to the transaction.
     */
    void add(const Instruction& ix);

    /**
     * @brief Serializes the transaction into a Solana message format.
     * @return A vector of bytes representing the serialized message.
     */
    std::vector<uint8_t> serializeMessage() const;

    /**
     * @brief Signs the transaction with the provided keypairs.
     * @param signers List of keypairs used to sign the transaction.
     */
    void sign(const std::vector<Keypair>& signers);

    /**
     * @brief Serializes the entire transaction and encodes it as Base64.
     * @return A Base64-encoded string representing the complete transaction.
     */
    String serializeBase64() const;
};

class IoTxChain {
public:
    // 1) Constructor
    /**
     * @brief Constructor that initializes the Solana RPC URL.
     * @param rpcUrl The RPC endpoint URL.
     */
    explicit IoTxChain(const String& rpcUrl);
    // Removed the external declaration of calculateDiscriminator
    //bugra
    std::vector<uint8_t> calculateDiscriminator(const std::string& functionName);


    // 2) sendSol
    /**
     * @brief Sends a native SOL transfer transaction using the System Program.
     * @param privateKeyBase58 Sender's private key in Base58 encoding.
     * @param fromPubkeyBase58 Sender's public key in Base58 encoding.
     * @param toPubkeyBase58 Recipient's public key in Base58 encoding.
     * @param lamports Amount of SOL to transfer, in lamports.
     * @return true if the transaction is successful, false otherwise.
     */
    //bugra
    bool sendSol(
        const String &privateKeyBase58,
        const String &fromPubkeyBase58,
        const String &toPubkeyBase58,
        uint64_t lamports
    );

    // 3) getSolBalance
    /**
     * @brief Retrieves the native SOL balance of a given wallet address.
     * @param walletPubkeyBase58 The wallet public key in Base58 format.
     * @param outLamports Output parameter for balance in lamports.
     * @return true if successful, false otherwise.
     */
    //bugra
    bool getSolBalance(const String& walletPubkeyBase58, uint64_t& outLamports);


    //bugra
    bool signMessageFromBase58(const std::vector<uint8_t> &message, const String &privateKeyBase58, uint8_t outSignature[64]);

    // 4) getSplTokenBalance
    /**
     * @brief Retrieves the SPL token balance for a wallet by querying its ATA.
     * 
     * First finds the ATA using findAssociatedTokenAccount, then queries the balance via "getTokenAccountBalance".
     * The returned balance is in base units. For human-readable value, divide by the token's decimals factor.
     * 
     * @param walletPubkeyBase58 Wallet's public key in Base58 encoding.
     * @param tokenMintBase58 Token mint's public key in Base58 encoding.
     * @param outBalance Output parameter for token balance (in base units).
     * @return true if balance is retrieved successfully, false otherwise.
     */
    //bugra
    bool getSplTokenBalance(
        const String& walletPubkeyBase58,
        const String& tokenMintBase58,
        uint64_t& outBalance
    );

    // 6) findAssociatedTokenAccount
    /**
     * @brief Finds the Associated Token Account (ATA) for a given owner and token mint.
     *
     * Queries the Solana RPC ("getTokenAccountsByOwner") using the owner and mint filter.
     *
     * @param ownerPubkeyBase58 Owner's public key in Base58 encoding.
     * @param mintPubkeyBase58 Token mint's public key in Base58 encoding.
     * @param outATA Output parameter to store the found ATA address.
     * @return true if the ATA is found, false otherwise.
     */
    //bugra
    bool findAssociatedTokenAccount(
        const String& ownerPubkeyBase58,
        const String& mintPubkeyBase58,
        String& outATA
    );

    // 8) getTokenDecimals
    /**
     * @brief Fetches the number of decimals used by a token mint.
     * @param mintPubkeyBase58 Token mint address in Base58.
     * @param outDecimals Output parameter to store decimals (e.g., 6 or 9).
     * @return true if successful, false otherwise.
     */
    //bugra
    bool getTokenDecimals(const String& mintPubkeyBase58, uint8_t& outDecimals);

    // 9) base64Encode
    //bugra
    String base64Encode(const uint8_t* data, size_t len);
    
    // 10) getLatestBlockhash
    //bugra
    String getLatestBlockhash();

    // 11) getBlockHeight
    //bugra
    bool getBlockHeight(uint64_t &outBlockHeight);

    // 12) getEpochInfo
    //bugra
    bool getEpochInfo(EpochInfo &outEpochInfo);
    
    //bugra
    bool signMessageRaw(const std::vector<uint8_t> &message, const std::vector<uint8_t> &privateKey, uint8_t outSignature[64]);

    // 14) sendRawTransaction
    /**
     * @brief Sends a raw transaction to the Solana network.
     * @param txBase64 The Base64 encoded transaction.
     * @param outSignature Output parameter for the transaction signature.
     * @return true if the transaction is sent successfully, false otherwise.
     */
    //bugra
    bool sendRawTransaction(
        const String &txBase64,
        String &outSignature
    );

    /**
     * @brief Confirms whether a transaction has been finalized or not.
     * 
     * This uses the "getSignatureStatuses" RPC method to check if a given signature
     * has been confirmed on the chain. It retries a few times before giving up.
     *
     * @param signature The Base58-encoded transaction signature.
     * @param maxWaitMs Maximum total wait time in milliseconds.
     * @return true if transaction is confirmed, false otherwise.
     */
    //bugra
    bool confirmTransaction(const String& signature, uint32_t maxWaitMs);

    bool sendProgramDataTransaction(const String &privateKeyBase58, const String &fromPubkeyBase58, const String &programIdBase58, const String &dataString, uint32_t confirmWaitMs);

    // 12) buildAndSignTransaction
    /**
     * @brief Builds and signs a basic transaction.
     * @param privateKey Sender's private key.
     * @param privLen Length of the private key.
     * @param fromPub Sender's public key.
     * @param toPub Recipient's public key.
     * @param lamports Amount of lamports to transfer.
     * @param recentBlockhash The latest blockhash.
     * @param outTxBase64 Output parameter for the Base64 encoded transaction.
     * @return true if successful, false otherwise.
     */
    //bugra
    bool buildAndSignTransaction(
        const uint8_t *privateKey,
        size_t privLen,
        const uint8_t *fromPub,
        const uint8_t *toPub,
        uint64_t lamports,
        const String &recentBlockhash,
        String &outTxBase64);




    //bugra
    bool findProgramAddress(
    const std::vector<std::vector<uint8_t>>& seeds,
    const std::vector<uint8_t>& programId,
    std::vector<uint8_t>& outPDA,
    uint8_t& outBump
);
private:
    String _rpcUrl;

        // 13) buildAndSignMemoTransaction
    /**
     * @brief Builds and signs a memo transaction.
     * @param privateKey Sender's private key.
     * @param privLen Length of the private key.
     * @param fromPub Sender's public key.
     * @param programIdBase58 Program ID for the memo or custom program.
     * @param dataString The memo or data string.
     * @param recentBlockhash The latest blockhash.
     * @param outTxBase64 Output parameter for the Base64 encoded transaction.
     * @return true if successful, false otherwise.
     */
    //bugra
    bool buildAndSignMemoTransaction(
        const uint8_t* privateKey,
        size_t privLen,
        const uint8_t* fromPub,
        const String &programIdBase58,
        const String &dataString,
        const String &recentBlockhash,
        String &outTxBase64
    );
};

// 16) encodeU64LE
/**
 * @brief Encodes a u64 number in little-endian format.
 * @param value The 64-bit unsigned integer to encode.
 * @return A vector containing the encoded bytes.
 */
std::vector<uint8_t> encodeU64LE(uint64_t value);

#endif // IoTxChain_LIB_H
