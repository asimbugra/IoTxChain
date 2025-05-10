#include "IoTxChain-lib.h"
extern "C" bool ed25519_decode_public_key(const uint8_t* buf) {
    return true;
}

static bool decodePointWrapper(const uint8_t hash[32]) {
    extern bool ed25519_decode_public_key(const uint8_t* buf);
    return !ed25519_decode_public_key(hash);
}

// (Optional) System Program ID (11111111111111111111111111111111) -> 
// Corresponds to 32 bytes: first byte = 0x01, remaining 31 bytes = 0x00
// This is here just as a reference; the actual value is derived using base58Decode.
static const uint8_t SYSTEM_PROGRAM_ID[32] = { /* ... */ };

// --------------------------------------------------------------------------------
// Constructor
// --------------------------------------------------------------------------------
IoTxChain::IoTxChain(const String& rpcUrl) {
    _rpcUrl = rpcUrl;
}

// --------------------------------------------------------------------------------
/**
 * @brief Fetches the latest blockhash from the Solana cluster.
 * 
 * This is required for building a new transaction. Each transaction must include
 * a recent blockhash to prevent replay attacks and ensure the transaction is processed
 * promptly. This function queries the RPC endpoint for the latest blockhash using
 * the "getLatestBlockhash" JSON-RPC method.
 * 
 * Retries the request up to 3 times if the network request or JSON parsing fails.
 * 
 * @return A String containing the latest blockhash in Base58 format, or an empty string on failure.
 */
// --------------------------------------------------------------------------------
String IoTxChain::getLatestBlockhash() {
    const int maxRetries = 3;  // Max retry attempts for HTTP call
    const int retryDelayMs = 500;  // Delay between retries in milliseconds

    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        Serial.printf("🌐 Attempting getLatestBlockhash (try %d/%d)...\n", attempt, maxRetries);

        WiFiClientSecure client;
        client.setInsecure(); // Disable SSL certificate validation (OK for ESP32)

        HTTPClient http;

        if (!http.begin(client, _rpcUrl)) {
            Serial.println("❌ HTTP begin failed. Check URL or SSL issue.");
            delay(retryDelayMs);
            continue;
        }

        http.addHeader("Content-Type", "application/json");

        // Construct the JSON-RPC request body
        String body = R"({
            "jsonrpc":"2.0",
            "id":1,
            "method":"getLatestBlockhash",
            "params":[]
        })";

        Serial.println("📡 Sending POST request...");
        int code = http.POST(body);

        if (code == 200) {
            // HTTP response received successfully
            String response = http.getString();
            Serial.println("✅ Response received:");
            Serial.println(response);
            http.end();

            // JSON parse
            DynamicJsonDocument doc(2048);
            auto err = deserializeJson(doc, response);
            if (err) {
                Serial.println("❌ JSON parse error in getLatestBlockhash");
                delay(retryDelayMs);
                continue;
            }

            // Parse JSON and extract the "blockhash" value
            String blockhash = doc["result"]["value"]["blockhash"].as<String>();
            if (blockhash.isEmpty()) {
                Serial.println("⚠️ Blockhash not found in response!");
                delay(retryDelayMs);
                continue;
            }

            Serial.println("✅ Latest Blockhash: " + blockhash);
            // Successfully fetched and parsed blockhash
            return blockhash;
        } else {
            Serial.printf("❌ HTTP code: %d\n", code);
            String resp = http.getString();
            Serial.println("🔁 Response: " + resp);
            http.end();
            delay(retryDelayMs);
        }
    }

    Serial.println("🚫 getLatestBlockhash failed after max retries.");
    // All retries failed, return empty string
    return "";
}

// --------------------------------------------------------------------------------
// Simple mbedTLS-based base64 encoding function
// --------------------------------------------------------------------------------
String IoTxChain::base64Encode(const uint8_t* data, size_t len) {
    // Calculate the required buffer size for Base64 encoding: 4 * ((len + 2) / 3)
    size_t requiredSize = 4 * ((len + 2) / 3);
    
    // Allocate buffer dynamically (plus one byte for the null terminator)
    char* outBuf = new char[requiredSize + 1];
    memset(outBuf, 0, requiredSize + 1);
    
    size_t olen = 0;
    // Perform Base64 encoding using mbedtls library
    int ret = mbedtls_base64_encode(reinterpret_cast<unsigned char*>(outBuf), requiredSize + 1, &olen, data, len);
    if (ret != 0) {
        // Encoding failed; log error and clean up
        Serial.println("Base64 encoding error (mbedtls), ret=" + String(ret));
        delete[] outBuf;
        return "";
    }
    
    // Construct the result String from the dynamically allocated buffer
    String result = String(outBuf).substring(0, olen);
    delete[] outBuf;
    return result;
}

// --------------------------------------------------------------------------------
//buildAndSignTransaction -> A simple transaction with a single "transfer" instruction
// --------------------------------------------------------------------------------
bool IoTxChain::buildAndSignTransaction(
    const uint8_t *privateKey, size_t privLen,
    const uint8_t *fromPub,
    const uint8_t *toPub,
    uint64_t lamports,
    const String &recentBlockhash,
    String &outTxBase64
) {
    // 1) Transaction header
    uint8_t numRequiredSignatures = 1;  // Only the sender signs
    uint8_t numReadOnlySigned = 0;
    uint8_t numReadOnlyUnsigned = 1;    // System program is read-only

    // 2) Decode the recent blockhash from Base58 (must be 32 bytes)
    uint8_t recentBlockhashBytes[32];
    size_t rbLen = sizeof(recentBlockhashBytes);
    if (!base58Decode(recentBlockhash, recentBlockhashBytes, rbLen) || rbLen != 32) {
        Serial.println("Blockhash decode failed or length != 32!");
        return false;
    }

    // 3) Transfer instruction data (4 bytes for instruction index '2' in LE + 8 bytes for lamports in LE)
    // Encode the transfer instruction data: first 4 bytes = instruction index (2),
    // next 8 bytes = lamports (amount to transfer) in little-endian format
    uint8_t instructionData[12];
    instructionData[0] = 0x02;
    instructionData[1] = 0x00;
    instructionData[2] = 0x00;
    instructionData[3] = 0x00;
    for (int i = 0; i < 8; i++) {
        instructionData[4 + i] = (uint8_t)((lamports >> (8 * i)) & 0xFF);
    }

    // 4) Message buffer
    uint8_t message[512];
    size_t offset = 0;

    // Add header values
    message[offset++] = numRequiredSignatures;
    message[offset++] = numReadOnlySigned;
    message[offset++] = numReadOnlyUnsigned;

    // Append number of accounts involved in transaction: from, to, and system program
    uint8_t accountCount = 3;
    message[offset++] = accountCount; // varuint = 3

    // Add sender (fromPub) public key
    memcpy(&message[offset], fromPub, 32);
    offset += 32;

    // Add recipient (toPub) public key
    memcpy(&message[offset], toPub, 32);
    offset += 32;

    // Add Solana System Program ID as the third account
    uint8_t systemProgram[32];
    size_t spLen = sizeof(systemProgram);
    base58Decode("11111111111111111111111111111111", systemProgram, spLen);
    memcpy(&message[offset], systemProgram, 32);
    offset += 32;

    // Append recent blockhash to message
    memcpy(&message[offset], recentBlockhashBytes, 32);
    offset += 32;

    // Number of instructions (1 transfer instruction)
    message[offset++] = 1;

    // Instruction: system program at index 2 is the program being invoked
    message[offset++] = 2;
    //  number of account indices = 2
    message[offset++] = 2;
    //  account indices = [0, 1]
    message[offset++] = 0;
    message[offset++] = 1;
    //  data length = 12 bytes
    message[offset++] = 12;
    // Instruction data for system transfer: index + lamports
    memcpy(&message[offset], instructionData, 12);
    offset += 12;

    size_t messageLen = offset;

    // 5) Ed25519 signing (privateKey: 64 bytes = 32-byte secret + 32-byte public)
    // Validate private key length
    if (privLen < 64) {
        Serial.println("Private key length < 64! Probably an invalid format.");
        return false;
    }

    const uint8_t* privKeyOnly = privateKey;        // first 32 bytes
    const uint8_t* pubKeyFromPriv = privateKey + 32; // last 32 bytes

    uint8_t signature[64];
    // Sign the serialized message using Ed25519
    Ed25519::sign(signature, privKeyOnly, pubKeyFromPriv, message, messageLen);

    // 6) Final transaction format: [sig_count=1, signature(64), message]
    uint8_t finalTx[1 + 64 + 512];
    size_t finalOffset = 0;

    // Construct final transaction format: [num signatures][signature][message]
    finalTx[finalOffset++] = 1;
    // Signature (64 bytes)
    memcpy(finalTx + finalOffset, signature, 64);
    finalOffset += 64;
    // Message
    memcpy(finalTx + finalOffset, message, messageLen);
    finalOffset += messageLen;

    // 7) Base64 encode the final transaction
    // Base64 encode the final transaction for RPC submission
    outTxBase64 = base64Encode(finalTx, finalOffset);
    if (outTxBase64.isEmpty()) {
        Serial.println("Base64 encode failed!");
        return false;
    }

    Serial.println("Base64 transaction: " + outTxBase64);
    return true;
}

/**
 * Signs a message with a binary Ed25519 private key.
 * This function expects the private key to be in raw binary format (64 bytes).
 * The private key format should be: [32 bytes secret key | 32 bytes public key]
 * 
 * - It checks if the private key is valid.
 * - It uses Ed25519 to sign the message.
 * - The signature is placed in the output buffer `outSignature`.
 * 
 * @param message Vector of bytes representing the message to sign.
 * @param privateKey A 64-byte vector: first 32 bytes = secret key, last 32 = public key.
 * @param outSignature A 64-byte buffer to hold the signature.
 * @return true if successful, false if key is invalid or signing fails.
 */
bool IoTxChain::signMessageRaw(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& privateKey,
    uint8_t outSignature[64]
) {
    if (privateKey.size() < 64) {
        // Ensure the private key is the correct length (64 bytes)
        Serial.println("signMessage: Invalid private key size");
        return false;
    }
    const uint8_t* priv = privateKey.data();
    const uint8_t* pub = privateKey.data() + 32;
    // Sign the message using Ed25519 (priv, pub, message, length)
    Ed25519::sign(outSignature, priv, pub, message.data(), message.size());
    return true;
}

// --------------------------------------------------------------------------------
//"sendRawTransaction" -> Uses JSON-RPC method "sendTransaction" with base64 encoding
// --------------------------------------------------------------------------------
bool IoTxChain::sendRawTransaction(const String &txBase64, String &outSignature) {
    // --------------------------------------------------------------------------------
    // Sends a Base64-encoded raw transaction to the Solana blockchain via JSON-RPC.
    // This method is typically used after signing a transaction and encoding it.
    // Returns true if broadcast was successful and outputs the transaction signature.
    // --------------------------------------------------------------------------------
    WiFiClientSecure client;
    // Create a secure WiFi client with insecure certificate validation (for ESP32)
    client.setInsecure(); // Skip certificate validation (for simplicity)
    HTTPClient http;

    if (!http.begin(client, _rpcUrl)) {
        Serial.println("HTTP begin failed for sendRawTransaction");
        return false;
    }

    // Set request headers for JSON-RPC
    http.addHeader("Content-Type", "application/json");

    // Construct JSON-RPC body with base64-encoded transaction data
    // Prepare JSON body with "method": "sendTransaction" and "encoding": "base64"
    String body = String() +
        R"({"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":[")" +
        txBase64 + 
        R"(",{"encoding":"base64","skipPreflight":false,"preflightCommitment":"confirmed"}]})";

    // Execute HTTP POST request
    int code = http.POST(body);
    if (code != 200) {
        Serial.printf("sendTransaction HTTP code: %d\n", code);
        String resp = http.getString();
        Serial.println("Response: " + resp);
        http.end();
        return false;
    }

    // Parse response and deserialize JSON
    String response = http.getString();
    http.end();

    DynamicJsonDocument doc(2048);
    auto err = deserializeJson(doc, response);
    if (err) {
        Serial.println("JSON parse error in sendTransaction");
        return false;
    }

    // Check for error field in the RPC response
    if (doc["error"]) {
        Serial.println("RPC Error: " + doc["error"]["message"].as<String>());
        return false;
    }

    // Extract transaction signature from result
    outSignature = doc["result"].as<String>();
    return true;
}


/**
 * @brief Builds and signs a simple transaction with a Memo instruction.
 *
 * This is commonly used for sending data to on-chain programs (like memo program),
 * or for minimal custom program interactions that include user-defined text.
 *
 * It constructs a Solana message using the provided signer, memo string, and target program,
 * signs it using Ed25519, and outputs the base64-encoded transaction.
 */
bool IoTxChain::buildAndSignMemoTransaction(
    const uint8_t* privateKey, 
    size_t privLen,
    const uint8_t* fromPub,
    const String &programIdBase58,
    const String &memoString,
    const String &recentBlockhash,
    String &outTxBase64
) {
    // --- Transaction header (required signer, readonly fields)
    uint8_t numRequiredSignatures = 1;  // Fee payer will sign
    uint8_t numReadOnlySigned     = 0;
    uint8_t numReadOnlyUnsigned   = 0; 

    // --- Decode the recent blockhash (used to prevent replay attacks)
    uint8_t recentBlockhashBytes[32];
    size_t rbLen = 32;
    if (!base58Decode(recentBlockhash, recentBlockhashBytes, rbLen) || rbLen != 32) {
        Serial.println("Blockhash decode or size error!");
        return false;
    }

    // --- Decode the on-chain program ID that will receive the instruction
    uint8_t programIdBytes[32];
    size_t pidLen = 32;
    if (!base58Decode(programIdBase58, programIdBytes, pidLen) || pidLen != 32) {
        Serial.println("Program ID decode error!");
        return false;
    }

    // --- Build the Solana message (header + accounts + blockhash + instructions)
    uint8_t message[512];
    size_t offset = 0;

    // Header: numRequiredSignatures, readOnlySigned, readOnlyUnsigned
    message[offset++] = numRequiredSignatures;
    message[offset++] = numReadOnlySigned;
    message[offset++] = numReadOnlyUnsigned;

    // Account list: fromPub (index 0), programId (index 1)
    uint8_t accountCount = 2;
    message[offset++] = accountCount;

    // fromPub
    memcpy(&message[offset], fromPub, 32);
    offset += 32;

    // programId
    memcpy(&message[offset], programIdBytes, 32);
    offset += 32;

    // recentBlockhash
    memcpy(&message[offset], recentBlockhashBytes, 32);
    offset += 32;

    // Instruction count = 1
    message[offset++] = 1;

    // Instruction: references program index + account indices
    // Single instruction:
    // programIdIndex = 1
    message[offset++] = 1;
    // number of account indices = 1
    message[offset++] = 1;
    // account index -> [0] (fromPub)
    message[offset++] = 0;

    // Encode the memo data with Solana's varuint format for string length
    uint32_t dataLen = memoString.length();
    if (dataLen < 128) {
        message[offset++] = (uint8_t)dataLen;
    } else {
        // Simple 2-byte varuint encoding
        message[offset++] = (uint8_t)((dataLen & 0x7F) | 0x80);
        message[offset++] = (uint8_t)(dataLen >> 7);
    }

    // Copy memo string bytes
    memcpy(&message[offset], memoString.c_str(), dataLen);
    offset += dataLen;

    size_t messageLen = offset;

    // --- Sign the serialized message using the private key
    if (privLen < 64) {
        Serial.println("Private key is not 64 bytes!");
        return false;
    }
    const uint8_t* privKeyOnly    = privateKey;
    const uint8_t* pubKeyFromPriv = privateKey + 32;

    uint8_t signature[64];
    Ed25519::sign(signature, privKeyOnly, pubKeyFromPriv, message, messageLen);

    // --- Final transaction = signature + message
    uint8_t finalTx[1 + 64 + 512];
    size_t finalOffset = 0;
    finalTx[finalOffset++] = 1;  // number of signatures
    memcpy(finalTx + finalOffset, signature, 64);
    finalOffset += 64;
    memcpy(finalTx + finalOffset, message, messageLen);
    finalOffset += messageLen;

    // --- Encode final binary transaction to Base64 for RPC submission
    outTxBase64 = base64Encode(finalTx, finalOffset);
    if (outTxBase64.isEmpty()) {
        Serial.println("Base64 encode failed!");
        return false;
    }

    // Debug print
    Serial.println("Parameterized Memo-like transaction (base64): " + outTxBase64);
    return true;
}

// Encode 64-bit little-endian integer
std::vector<uint8_t> encodeU64LE(uint64_t value) {
    std::vector<uint8_t> result(8);
    for (int i = 0; i < 8; i++) {
        result[i] = (uint8_t)((value >> (8 * i)) & 0xFF);
    }
    return result;
}

/**
 * Converts a Base58-encoded public key string into a 32-byte binary vector.
 * 
 * This is used to decode public key strings (commonly used in Solana)
 * into their binary representation for low-level transaction construction.
 * 
 * @param base58Str The public key in Base58 encoding.
 * @return A 32-byte vector containing the decoded public key.
 *         If decoding fails or result is not 32 bytes, an empty vector is returned.
 */
std::vector<uint8_t> base58ToPubkey(const String& base58Str) {
    uint8_t buffer[32];
    size_t len = sizeof(buffer);
    if (!base58Decode(base58Str, buffer, len) || len != 32) {
        Serial.println("❌ base58ToPubkey: Invalid base58 input!");
        return {};
    }
    return std::vector<uint8_t>(buffer, buffer + 32);
}


// ----------------------------------------------------------------------
// Function: findAssociatedTokenAccount
// ----------------------------------------------------------------------
/**
 * @brief Finds the Associated Token Account (ATA) for a given owner and token mint.
 * 
 * Queries the Solana RPC ("getTokenAccountsByOwner") using the owner and mint filter.
 * 
 * @param ownerPubkeyBase58 Owner's public key in Base58.
 * @param mintPubkeyBase58 Token mint's public key in Base58.
 * @param outATA Output parameter to store the found ATA address.
 * @return true if the ATA is found, false otherwise.
 */
bool IoTxChain::findAssociatedTokenAccount(
    const String& ownerPubkeyBase58,
    const String& mintPubkeyBase58,
    String& outATA
) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;
    if (!http.begin(client, _rpcUrl)) {
        Serial.println("findAssociatedTokenAccount: HTTP begin failed");
        return false;
    }
    String body = String() +
        R"({"jsonrpc":"2.0","id":1,"method":"getTokenAccountsByOwner","params":[")" +
        ownerPubkeyBase58 +
        R"(",{"mint":")" + mintPubkeyBase58 + R"("},{"encoding":"jsonParsed"}]})";
    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);
    if (code != 200) {
        Serial.printf("findAssociatedTokenAccount HTTP code: %d\n", code);
        Serial.println("Response: " + http.getString());
        http.end();
        return false;
    }
    String response = http.getString();
    http.end();
    DynamicJsonDocument doc(4096);
    DeserializationError error = deserializeJson(doc, response);
    if (error) {
        Serial.println("findAssociatedTokenAccount: JSON parse error");
        return false;
    }
    if (doc["error"]) {
        Serial.println("findAssociatedTokenAccount RPC Error: " + doc["error"]["message"].as<String>());
        return false;
    }
    JsonArray arr = doc["result"]["value"].as<JsonArray>();
    if (!arr || arr.size() == 0) {
        Serial.println("findAssociatedTokenAccount: No ATA found for given owner and mint");
        return false;
    }
    outATA = arr[0]["pubkey"].as<String>();
    return true;
}

// ----------------------------------------------------------------------
// Function: getSplTokenBalance
// ----------------------------------------------------------------------
/**
 * @brief Retrieves the SPL token balance for a wallet by querying its ATA.
 * 
 * This function first uses `findAssociatedTokenAccount` to locate the
 * Associated Token Account (ATA) for the given wallet and mint. Then,
 * it sends a JSON-RPC request to retrieve the SPL token balance from
 * the Solana blockchain using "getTokenAccountBalance".
 * 
 * This method is useful for applications that need to display or verify
 * the balance of a specific token (other than SOL) in a user's wallet.
 * 
 * @param walletPubkeyBase58 Wallet's public key in Base58 encoding.
 * @param tokenMintBase58 Token mint's public key in Base58 encoding.
 * @param outBalance Output parameter to store the retrieved balance.
 * @return true if the balance is successfully retrieved, false otherwise.
 */
bool IoTxChain::getSplTokenBalance(
    const String& walletPubkeyBase58,
    const String& tokenMintBase58,
    uint64_t& outBalance
) {
    String ataAddress;
    if (!findAssociatedTokenAccount(walletPubkeyBase58, tokenMintBase58, ataAddress)) {
        Serial.println("getSplTokenBalance: ATA not found, balance = 0 assumed");
        outBalance = 0;
        return true;
    }
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;
    if (!http.begin(client, _rpcUrl)) {
        Serial.println("getSplTokenBalance: HTTP begin failed");
        return false;
    }
    String body = String() +
        R"({"jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":[")" +
        ataAddress + R"("]})";
    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);
    if (code != 200) {
        Serial.printf("getTokenAccountBalance HTTP code: %d\n", code);
        Serial.println("Response: " + http.getString());
        http.end();
        return false;
    }
    String response = http.getString();
    http.end();
    DynamicJsonDocument doc(2048);
    DeserializationError err = deserializeJson(doc, response);
    if (err) {
        Serial.println("getSplTokenBalance: JSON parse error");
        return false;
    }
    if (doc["error"]) {
        Serial.println("getSplTokenBalance RPC Error: " + doc["error"]["message"].as<String>());
        return false;
    }
    String amountStr = doc["result"]["value"]["amount"].as<String>();
    if (amountStr.isEmpty()) {
        Serial.println("getSplTokenBalance: Balance field not found!");
        return false;
    }
    outBalance = strtoull(amountStr.c_str(), nullptr, 10);
    return true;
}


/**
 * @brief Retrieves the native SOL balance of a given wallet address.
 *        Uses the "getBalance" RPC method and decodes the lamport amount.
 *
 * This method:
 * - Sends an HTTP POST request to the configured RPC endpoint
 * - Queries the balance using the provided Base58-encoded public key
 * - Deserializes the response and extracts the balance
 * - Returns true on success, false on failure
 *
 * @param walletPubkeyBase58 The wallet public key in Base58 format.
 * @param outLamports Output parameter for balance in lamports.
 * @return true if successful, false otherwise.
 */
bool IoTxChain::getSolBalance(const String& walletPubkeyBase58, uint64_t& outLamports) {
    WiFiClientSecure client;
    client.setInsecure(); // Disable SSL cert validation for simplicity

    HTTPClient http;

    // Begin HTTP connection with given RPC endpoint
    if (!http.begin(client, _rpcUrl)) {
        Serial.println("getSolBalance: HTTP begin failed");
        return false;
    }

    // Construct JSON-RPC request body to get SOL balance
    String body = String() +
        R"({"jsonrpc":"2.0","id":1,"method":"getBalance","params":[")" +
        walletPubkeyBase58 + R"("]})";

    http.addHeader("Content-Type", "application/json");

    // Send the HTTP POST request
    int code = http.POST(body);
    if (code != 200) {
        Serial.printf("getSolBalance HTTP error: %d\n", code);
        http.end();
        return false;
    }

    // Read response
    String response = http.getString();
    http.end();

    // Parse JSON and check for errors
    DynamicJsonDocument doc(2048);
    if (deserializeJson(doc, response)) {
        Serial.println("getSolBalance: JSON parse error");
        return false;
    }

    if (doc["error"]) {
        Serial.println("getSolBalance RPC Error: " + doc["error"]["message"].as<String>());
        return false;
    }

    // Extract and assign the balance in lamports
    outLamports = doc["result"]["value"];
    return true;
}

/**
 * @brief Signs an arbitrary message using an Ed25519 private key encoded in Base58.
 * 
 * This function allows signing binary messages (vector<uint8_t>) using a Solana-style
 * Base58-encoded private key. It performs the following steps:
 * 
 * - Decodes the Base58 private key (must be 64 bytes after decode).
 * - Extracts the secret and public key from the decoded buffer.
 * - Signs the message using the Ed25519 algorithm.
 * - Stores the 64-byte signature in the provided output buffer.
 * 
 * This is typically used to generate signatures for messages that will later be verified
 * by on-chain programs or off-chain verifiers.
 *
 * @param message Vector of bytes to be signed.
 * @param privateKeyBase58 Private key in Base58 format. Must decode to 64 bytes.
 * @param outSignature Output buffer (64 bytes) where the signature will be stored.
 * @return true if signing was successful, false otherwise.
 */
bool IoTxChain::signMessageFromBase58(
    const std::vector<uint8_t>& message,
    const String& privateKeyBase58,
    uint8_t outSignature[64]
) {
    uint8_t privateKey[128];
    size_t privateKeyLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privateKeyLen) || privateKeyLen < 64) {
        Serial.println("signMessage: Failed to decode private key");
        return false;
    }

    const uint8_t* priv = privateKey;
    const uint8_t* pub = privateKey + 32;

    Ed25519::sign(outSignature, priv, pub, message.data(), message.size());
    return true;
}


/**
 * @brief Fetches the number of decimals used by a token mint.
 * 
 * This function queries the Solana blockchain using the "getTokenSupply" RPC method
 * to retrieve the metadata of a given SPL token mint. Specifically, it extracts the
 * "decimals" field, which defines how many decimal places the token supports (e.g., 6 or 9).
 * 
 * This is important when displaying or converting token amounts from their raw integer
 * representation (in the smallest unit) to a human-readable format.
 * 
 * Example: If a token has 6 decimals and the amount is 123456789, it should be displayed as 123.456789.
 * 
 * @param mintPubkeyBase58 Token mint address in Base58 format.
 * @param outDecimals Output parameter to store the number of decimals found (0–255).
 * @return true if successful, false if the RPC fails or parsing fails.
 */
bool IoTxChain::getTokenDecimals(const String& mintPubkeyBase58, uint8_t& outDecimals) {
    WiFiClientSecure client;
    client.setInsecure();  // Accept all certificates (OK for embedded devices)

    HTTPClient http;
    if (!http.begin(client, _rpcUrl)) {
        Serial.println("getTokenDecimals: HTTP begin failed");
        return false;
    }

    // JSON-RPC body to fetch token supply info (which includes decimals)
    String body = String() +
        R"({"jsonrpc":"2.0","id":1,"method":"getTokenSupply","params":[")" +
        mintPubkeyBase58 + R"("]})";

    http.addHeader("Content-Type", "application/json");
    int code = http.POST(body);

    if (code != 200) {
        Serial.printf("getTokenDecimals HTTP error: %d\n", code);
        http.end();
        return false;
    }

    String response = http.getString();
    http.end();

    // Parse JSON and extract the "decimals" field
    DynamicJsonDocument doc(4096);
    DeserializationError error = deserializeJson(doc, response);
    if (error) {
        Serial.println("getTokenDecimals: JSON parse error");
        return false;
    }

    if (doc["error"]) {
        Serial.println("getTokenDecimals RPC Error: " + doc["error"]["message"].as<String>());
        return false;
    }

    JsonVariant decimals = doc["result"]["value"]["decimals"];
    if (decimals.isNull()) {
        Serial.println("getTokenDecimals: Decimals not found in response");
        return false;
    }

    outDecimals = decimals.as<uint8_t>();
    return true;
}


/**
 * @brief Fetches the current block height from the Solana blockchain.
 * 
 * This function sends a JSON-RPC request to the configured RPC endpoint using
 * the "getBlockHeight" method. The returned value indicates the current block height
 * on the chain. This is useful for tracking blockchain progression or syncing events.
 *
 * @param outBlockHeight Output parameter to store the returned block height.
 * @return true if the request succeeds and the height is extracted, false otherwise.
 */
bool IoTxChain::getBlockHeight(uint64_t &outBlockHeight) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;
    if (!http.begin(client, _rpcUrl)) {
        Serial.println("getBlockHeight: HTTP begin failed");
        return false;
    }
    http.addHeader("Content-Type", "application/json");
    String body = R"({"jsonrpc":"2.0","id":1,"method":"getBlockHeight","params":[]})";
    int code = http.POST(body);
    if (code != 200) {
        Serial.printf("getBlockHeight HTTP error: %d\n", code);
        http.end();
        return false;
    }
    String response = http.getString();
    http.end();
    DynamicJsonDocument doc(1024);
    DeserializationError error = deserializeJson(doc, response);
    if (error) {
        Serial.println("getBlockHeight: JSON parse error");
        return false;
    }
    outBlockHeight = doc["result"].as<uint64_t>();
    return true;
}

/**
 * @brief Retrieves the current epoch information from the Solana blockchain.
 * 
 * This function performs a JSON-RPC request to fetch epoch metadata including:
 * - The absolute slot number
 * - Current block height
 * - Epoch number
 * - Slot index within the epoch
 * - Total number of slots in the epoch
 *
 * This information is essential for validators, dApps or DePIN systems needing
 * time-based logic or performance insights.
 * 
 * @param outEpochInfo Reference to a structure where epoch data will be stored.
 * @return true if successful, false on HTTP or JSON parsing failure.
 */
bool IoTxChain::getEpochInfo(EpochInfo &outEpochInfo) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;
    if (!http.begin(client, _rpcUrl)) {
        Serial.println("getEpochInfo: HTTP begin failed");
        return false;
    }
    http.addHeader("Content-Type", "application/json");
    String body = R"({"jsonrpc":"2.0","id":1,"method":"getEpochInfo","params":[]})";
    int code = http.POST(body);
    if (code != 200) {
        Serial.printf("getEpochInfo HTTP error: %d\n", code);
        http.end();
        return false;
    }
    String response = http.getString();
    http.end();
    DynamicJsonDocument doc(2048);
    DeserializationError error = deserializeJson(doc, response);
    if (error) {
        Serial.println("getEpochInfo: JSON parse error");
        return false;
    }
    JsonObject result = doc["result"].as<JsonObject>();
    outEpochInfo.absoluteSlot = result["absoluteSlot"].as<uint64_t>();
    outEpochInfo.blockHeight  = result["blockHeight"].as<uint64_t>();
    outEpochInfo.epoch        = result["epoch"].as<uint64_t>();
    outEpochInfo.slotIndex    = result["slotIndex"].as<uint64_t>();
    outEpochInfo.slotsInEpoch = result["slotsInEpoch"].as<uint64_t>();
    return true;
}



/**
 * Adds an instruction to the transaction.
 * This appends the instruction to the list of instructions that will be included
 * when serializing and signing the transaction.
 */
void Transaction::add(const Instruction& ix) {
    instructions.push_back(ix);
}

/**
 * Serializes the transaction into the message format expected by Solana.
 * 
 * The message consists of:
 * - header (num of required signatures, read-only accounts etc.)
 * - account keys (unique list of all keys used in the instructions)
 * - recent blockhash (decoded from Base58)
 * - instructions (each encoded with program ID index, account indices, and data)
 * 
 * @return Serialized message as vector of bytes
 */
std::vector<uint8_t> Transaction::serializeMessage() const {
    std::vector<uint8_t> msg;
    msg.push_back(1); msg.push_back(0); msg.push_back(0);

    std::vector<Pubkey> accountKeys;
    auto add_unique_key = [&](const Pubkey& k) {
        for (const auto& existing : accountKeys)
            if (existing.data == k.data) return;
        accountKeys.push_back(k);
    };

    add_unique_key(fee_payer);
    for (const auto& ix : instructions) {
        for (const auto& acct : ix.accounts) add_unique_key(acct.pubkey);
        add_unique_key(ix.programId);
    }

    msg.push_back(accountKeys.size());
    for (const auto& k : accountKeys)
        msg.insert(msg.end(), k.data.begin(), k.data.end());

    uint8_t decoded[64];
    size_t outLen = sizeof(decoded);
    if (base58Decode(recent_blockhash, decoded, outLen)) {
        msg.insert(msg.end(), decoded, decoded + outLen);
    }

    msg.push_back(instructions.size());
    for (const auto& ix : instructions) {
        uint8_t program_id_index = 0;
        for (size_t i = 0; i < accountKeys.size(); ++i) {
            if (accountKeys[i].data == ix.programId.data) {
                program_id_index = i;
                break;
            }
        }

        msg.push_back(program_id_index);
        msg.push_back(ix.accounts.size());
        for (const auto& acct : ix.accounts) {
            for (size_t i = 0; i < accountKeys.size(); ++i) {
                if (accountKeys[i].data == acct.pubkey.data) {
                    msg.push_back(i);
                    break;
                }
            }
        }

        msg.push_back(ix.data.size());
        msg.insert(msg.end(), ix.data.begin(), ix.data.end());
    }

    return msg;
}



/**
 * Signs the transaction message using the first keypair in the provided signer list.
 * 
 * This method:
 * - Serializes the transaction into a Solana message format
 * - Uses the first `Keypair` to sign the message via Ed25519
 * - Stores the resulting signature in the transaction's `signature` field
 */
void Transaction::sign(const std::vector<Keypair>& signers) {
    extern IoTxChain solana;
    // Serialize transaction into message format
    std::vector<uint8_t> msg = serializeMessage();

    // Ensure at least one signer is provided
    if (signers.empty()) return;
    // Use the first signer to sign the message
    const Keypair& signer = signers[0];
    // Check that private key is 64 bytes (32-byte secret + 32-byte public)
    if (signer.privkey.size() < 64) {
        Serial.println("Invalid private key format, expected binary 64 bytes.");
        return;
    }

    // Resize signature buffer
    signature.resize(64);
    // Sign the message and store in signature field
    if (!solana.signMessageRaw(msg, signer.privkey, signature.data())) {
        Serial.println("❌ Signature failed.");
    }
}

/**
 * Serializes the transaction into a base64-encoded format for submission to the Solana RPC.
 * 
 * This includes:
 * - Prefixing the message with the number of signatures (1)
 * - Appending the Ed25519 signature (64 bytes)
 * - Adding the serialized message
 * 
 * The final byte array is then Base64-encoded using the library utility.
 */
String Transaction::serializeBase64() const {
    // Serialize message body
    std::vector<uint8_t> msg = serializeMessage();

    // Compose final transaction: [num signatures][signature][message]
    std::vector<uint8_t> finalTx;
    finalTx.push_back(1); // one signature
    finalTx.insert(finalTx.end(), signature.begin(), signature.end());
    finalTx.insert(finalTx.end(), msg.begin(), msg.end());

    // Encode transaction into base64 for RPC submission
    IoTxChain lib(""); // Temporary instance for base64 encoding
    return lib.base64Encode(finalTx.data(), finalTx.size());
}
 
/**
 * Converts a Base58-encoded string into a Pubkey object.
 * This is useful for decoding human-readable public keys into binary format for transactions.
 *
 * @param str A Base58-encoded public key string.
 * @return A Pubkey object with 32-byte binary data.
 */
Pubkey Pubkey::fromBase58(const String& str) {
    Pubkey pk;
    pk.data = base58ToPubkey(str);
    return pk;
}

/**
 * Constructs a Keypair object from a 64-byte private key.
 * The private key format should be: [32 bytes secret key | 32 bytes public key]
 *
 * @param key64 Pointer to a 64-byte array containing the private key.
 * @return A Keypair with populated private and public key fields.
 */
Keypair Keypair::fromPrivateKey(const uint8_t* key64) {
    Keypair kp;
    kp.privkey = std::vector<uint8_t>(key64, key64 + 64);
    kp.pubkey_ = Pubkey{std::vector<uint8_t>(key64 + 32, key64 + 64)};
    return kp;
}

/**
 * Returns the public key associated with this Keypair.
 * 
 * @return A reference to the internal Pubkey object.
 */
const Pubkey& Keypair::pubkey() const {
    return pubkey_;
}
 
// AccountMeta
/**
 * @brief Creates a signer account meta.
 * 
 * This function is used when an account needs to sign the transaction.
 * The `isSigner` flag will be set to true and `isWritable` will be false.
 *
 * @param key The public key of the account.
 * @return An AccountMeta instance representing a signer.
 */
AccountMeta AccountMeta::signer(const Pubkey& key) {
    return AccountMeta{key, true, false};
}
/**
 * @brief Creates a writable account meta.
 * 
 * This function is used when an account needs to be marked as writable.
 * You can optionally specify whether this account is also a signer.
 *
 * @param key The public key of the account.
 * @param isSigner Boolean indicating if the account is also a signer.
 * @return An AccountMeta instance with writable and optional signer flags.
 */
AccountMeta AccountMeta::writable(const Pubkey& key, bool isSigner) {
    return AccountMeta{key, isSigner, true};
}
 
// Instruction
/**
 * @brief Constructs a new Solana instruction object.
 * 
 * An instruction consists of a program ID (which identifies the program to invoke),
 * a list of accounts that will be passed to the program, and the binary-encoded instruction data.
 * 
 * @param pid The program ID this instruction will call.
 * @param accts A list of AccountMeta objects representing accounts involved.
 * @param d Binary data to be passed as instruction arguments.
 */
Instruction::Instruction(const Pubkey& pid, const std::vector<AccountMeta>& accts, const std::vector<uint8_t>& d)
    : programId(pid), accounts(accts), data(d) {}



/**
 * @brief Calculates the 8-byte Anchor discriminator from a given function name.
 *
 * Anchor smart contracts use the first 8 bytes of the SHA-256 hash of
 * the string "global:functionName" as a unique function identifier.
 *
 * This discriminator is prepended to instruction data for Anchor-compatible transactions.
 *
 * @param functionName The name of the function defined in the Anchor program (e.g., "update_temperature").
 * @return A vector containing the first 8 bytes of the SHA-256 hash, which serves as the discriminator.
 */
std::vector<uint8_t> IoTxChain::calculateDiscriminator(const std::string& functionName) {
    std::string input = "global:" + functionName;

    uint8_t hash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);  // 0 for SHA-256
    mbedtls_sha256_update_ret(&ctx, (const uint8_t*)input.c_str(), input.size());
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    return std::vector<uint8_t>(hash, hash + 8);
}

/**
 * @brief Derives a PDA and bump seed using the same logic as Solana's findProgramAddressSync.
 * 
 * This replicates the on-chain derivation using SHA256 and ed25519 verification tests.
 * 
 * @param seeds Vector of byte arrays (seeds) to use in address derivation.
 * @param programId 32-byte program ID.
 * @param outPDA Output buffer (32 bytes) for the resulting PDA.
 * @param outBump Output bump seed that led to a valid PDA.
 * @return true if successful, false otherwise.
 */
bool IoTxChain::findProgramAddress(
    const std::vector<std::vector<uint8_t>>& seeds,
    const std::vector<uint8_t>& programId,
    std::vector<uint8_t>& outPDA,
    uint8_t& outBump
) {
    const std::string marker = "ProgramDerivedAddress";

    for (int bump = 255; bump >= 0; --bump) {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts_ret(&ctx, 0); // 0 = SHA256

        for (const auto& seed : seeds)
            mbedtls_sha256_update_ret(&ctx, seed.data(), seed.size());

        uint8_t bumpByte = static_cast<uint8_t>(bump);
        mbedtls_sha256_update_ret(&ctx, &bumpByte, 1);
        mbedtls_sha256_update_ret(&ctx, programId.data(), programId.size());
        mbedtls_sha256_update_ret(&ctx, (const uint8_t*)marker.c_str(), marker.size());

        uint8_t hash[32];
        mbedtls_sha256_finish_ret(&ctx, hash);
        mbedtls_sha256_free(&ctx);

        bool isValid = decodePointWrapper(hash);

        if (isValid) {
            continue;
        }
        outPDA.assign(hash, hash + 32);
        outBump = bump;
        return true;
    }

    Serial.println("❌ No valid PDA found");
    return false;
}




/**
 * @brief Confirms whether a transaction has been finalized or not.
 * 
 * Uses the "getSignatureStatuses" RPC method to check if a given signature
 * has been confirmed on the Solana blockchain. Retries for a limited time.
 *
 * @param signature The Base58-encoded transaction signature.
 * @param maxWaitMs Maximum wait time in milliseconds for confirmation.
 * @return true if confirmed, false otherwise.
 */
bool IoTxChain::confirmTransaction(const String& signature, uint32_t maxWaitMs) {
    const uint32_t pollIntervalMs = 500;
    uint32_t waited = 0;

    while (waited <= maxWaitMs) {
        WiFiClientSecure client;
        client.setInsecure();
        HTTPClient http;

        if (!http.begin(client, _rpcUrl)) {
            Serial.println("confirmTransaction: HTTP begin failed");
            return false;
        }

        String body = String() +
            R"({"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[[")" +
            signature +
            R"("],{"searchTransactionHistory":true}]})";

        http.addHeader("Content-Type", "application/json");

        int code = http.POST(body);
        if (code != 200) {
            Serial.printf("confirmTransaction HTTP error: %d\n", code);
            http.end();
            delay(pollIntervalMs);
            waited += pollIntervalMs;
            continue;
        }

        String response = http.getString();
        http.end();

        DynamicJsonDocument doc(2048);
        auto err = deserializeJson(doc, response);
        if (err) {
            Serial.println("confirmTransaction: JSON parse error");
            delay(pollIntervalMs);
            waited += pollIntervalMs;
            continue;
        }

        JsonVariant status = doc["result"]["value"][0];
        if (!status.isNull()) {
            bool errNull = status["err"].isNull();
            String confStatus = status["confirmationStatus"] | "";

            Serial.println("📋 Transaction Status: " + confStatus);
            if ((confStatus == "confirmed" || confStatus == "finalized") && errNull) {
                Serial.println("✅ Transaction is confirmed.");
                return true;
            }
        }

        delay(pollIntervalMs);
        waited += pollIntervalMs;
    }

    Serial.println("⏱️ Timeout: Transaction not confirmed within limit.");
    return false;
}


/**
 * @brief Sends arbitrary data to a Solana program (e.g., Memo or custom).
 * 
 * Combines: 
 * - Base58 decoding of keys,
 * - Blockhash fetch,
 * - Transaction construction + signing,
 * - Broadcast + confirmation.
 * 
 * @param privateKeyBase58   Sender's private key in Base58 (64-byte).
 * @param fromPubkeyBase58   Sender's public key in Base58.
 * @param programIdBase58    Target program ID (Base58).
 * @param dataString         Data string (memo or other) to send.
 * @param confirmWaitMs      Milliseconds to wait for confirmation (default 5000).
 * @return true if transaction sent and confirmed, false otherwise.
 */
bool IoTxChain::sendProgramDataTransaction(
    const String &privateKeyBase58,
    const String &fromPubkeyBase58,
    const String &programIdBase58,
    const String &dataString,
    uint32_t confirmWaitMs = 5000
) {
    // --- Decode private key ---
    uint8_t privateKey[128];
    size_t privateKeyLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privateKeyLen) || privateKeyLen < 64) {
        Serial.println("❌ Private key decode error!");
        return false;
    }

    // --- Decode public key ---
    uint8_t fromPub[32];
    size_t fromLen = sizeof(fromPub);
    if (!base58Decode(fromPubkeyBase58, fromPub, fromLen) || fromLen != 32) {
        Serial.println("❌ fromPubkey decode error!");
        return false;
    }

    // --- Get latest blockhash ---
    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) {
        Serial.println("❌ Failed to fetch blockhash!");
        return false;
    }

    // --- Build + Sign ---
    String txBase64;
    if (!buildAndSignMemoTransaction(privateKey, privateKeyLen, fromPub, programIdBase58, dataString, blockhash, txBase64)) {
        Serial.println("❌ Failed to build and sign transaction!");
        return false;
    }

    // --- Send ---
    String signature;
    if (!sendRawTransaction(txBase64, signature)) {
        Serial.println("❌ Failed to send transaction!");
        return false;
    }

    Serial.println("✅ Tx Signature: " + signature);

    // --- Confirm ---
    if (!confirmTransaction(signature, confirmWaitMs)) {
        Serial.println("⚠️ Transaction NOT confirmed in time.");
        return false;
    }

    Serial.println("✅ Transaction confirmed.");
    return true;
}


// --------------------------------------------------------------------------------
// "sendSolTransaction" -> Main function to be called externally for SOL transfer
// --------------------------------------------------------------------------------
bool IoTxChain::sendSol(
    const String &privateKeyBase58,
    const String &fromPubkeyBase58,
    const String &toPubkeyBase58,
    uint64_t lamports
) {
    // 1) Decode private key from Base58
    uint8_t privateKey[128];
    size_t privateKeyLen = sizeof(privateKey);
    if (!base58Decode(privateKeyBase58, privateKey, privateKeyLen)) {
        Serial.println("Private key base58 decode error!");
        return false;
    }

    // 2) Decode sender public key
    uint8_t fromPub[32];
    size_t fromLen = 32;
    if (!base58Decode(fromPubkeyBase58, fromPub, fromLen) || fromLen != 32) {
        Serial.println("fromPubkey decode error!");
        return false;
    }

    // 3) Decode recipient public key
    uint8_t toPub[32];
    size_t toLen = 32;
    if (!base58Decode(toPubkeyBase58, toPub, toLen) || toLen != 32) {
        Serial.println("toPubkey decode error!");
        return false;
    }

    // 4) Fetch latest blockhash from the network
    String blockhash = getLatestBlockhash();
    if (blockhash.isEmpty()) {
        Serial.println("Failed to retrieve blockhash!");
        return false;
    }

    // 5) Build and sign the transaction
    String txBase64;
    if (!buildAndSignTransaction(privateKey, privateKeyLen, fromPub, toPub, lamports, blockhash, txBase64)) {
        Serial.println("Transaction build/sign error!");
        return false;
    }

    // 6) Send the transaction to the RPC endpoint
    String signature;
    if (!sendRawTransaction(txBase64, signature)) {
        Serial.println("Transaction broadcast error!");
        return false;
    }

    // 7) If successful, print the transaction signature (Tx hash)
    Serial.println("Transaction Signature: " + signature);
    return true;
}
