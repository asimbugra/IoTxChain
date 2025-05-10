
#include <Arduino.h>
#include <WiFi.h>
#include "IoTxChain-lib.h"

// // WiFi credentials
const char* ssid     = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";


// Solana RPC URL (Devnet)
const String solanaRpcUrl = "https://api.devnet.solana.com"; // or mainnet/testnet

// Your Solana wallet (Base58 format)
const String PRIVATE_KEY_BASE58 = "PRIVATE_KEY_BASE58";  // 64-byte base58
const String PUBLIC_KEY_BASE58     = "PUBLIC_KEY_BASE58";

// Recipient
const String toPubkeyBase58       = "toPubkeyBase58";

const String ProgramIdBase58  = "ProgramIdBase58";

// 🪙 SPL Token Mint Address (Base58)
// Example: USDC Devnet = Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr
const String tokenMintBase58 = "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr";

// Initialize Solana Library
IoTxChain solana(solanaRpcUrl);

void example_getSolBalance() {
    Serial.println("\n=== 🔹 getSolBalance() ===");

    const String wallet = PUBLIC_KEY_BASE58;
    uint64_t lamports = 0;

    if (solana.getSolBalance(wallet, lamports)) {
        Serial.print("SOL Balance (lamports): ");
        Serial.println(lamports);
        Serial.print("SOL Balance (SOL): ");
        Serial.println((float)lamports / 1e9, 9);
    } else {
        Serial.println("❌ Failed to fetch SOL balance.");
    }
}

void example_getSplTokenBalance() {
    Serial.println("\n=== 🔹 getSplTokenBalance() ===");

    uint64_t rawBalance = 0;

    if (solana.getSplTokenBalance(PUBLIC_KEY_BASE58, tokenMintBase58, rawBalance)) {
        float readableBalance = (float)rawBalance / 1e6;
        Serial.print("Token Balance: ");
        Serial.println(readableBalance, 6);
    } else {
        Serial.println("❌ Failed to get SPL token balance.");
    }
}

void example_getTokenDecimals() {
    Serial.println("\n=== 🔹 getTokenDecimals() ===");

    uint8_t decimals = 0;
    if (solana.getTokenDecimals(tokenMintBase58, decimals)) {
        Serial.print("Decimals: ");
        Serial.println(decimals);
    } else {
        Serial.println("❌ Failed to get token decimals.");
    }
}

void example_getLatestBlockhash() {
    Serial.println("\n=== 🔹 getLatestBlockhash() ===");

    String blockhash = solana.getLatestBlockhash();
    if (!blockhash.isEmpty()) {
        Serial.print("Latest Blockhash: ");
        Serial.println(blockhash);
    } else {
        Serial.println("❌ Failed to get blockhash.");
    }
}

void example_getBlockHeight() {
    Serial.println("\n=== 🔹 getBlockHeight() ===");

    uint64_t blockHeight = 0;
    if (solana.getBlockHeight(blockHeight)) {
        Serial.print("Current Block Height: ");
        Serial.println(blockHeight);
    } else {
        Serial.println("❌ Failed to get block height.");
    }
}

void example_getEpochInfo() {
    Serial.println("\n=== 🔹 getEpochInfo() ===");

    EpochInfo info;
    if (solana.getEpochInfo(info)) {
        Serial.println("✅ Epoch Info:");
        Serial.print("  Absolute Slot: "); Serial.println(info.absoluteSlot);
        Serial.print("  Block Height : "); Serial.println(info.blockHeight);
        Serial.print("  Epoch        : "); Serial.println(info.epoch);
        Serial.print("  Slot Index   : "); Serial.println(info.slotIndex);
        Serial.print("  Slots/Epoch  : "); Serial.println(info.slotsInEpoch);
    } else {
        Serial.println("❌ Failed to get epoch info.");
    }
}

void example_signMessageFromBase58() {
    Serial.println("\n=== 🔹 signMessageFromBase58() ===");

    std::vector<uint8_t> msg = {'I', 'o', 'T', 'x', 'C', 'h', 'a', 'i', 'n'};
    uint8_t sig[64];

    if (solana.signMessageFromBase58(msg, PRIVATE_KEY_BASE58, sig)) {
        Serial.print("Signature: ");
        for (int i = 0; i < 64; ++i) {
            if (sig[i] < 16) Serial.print("0");
            Serial.print(sig[i], HEX);
        }
        Serial.println();
    } else {
        Serial.println("❌ Failed to sign message.");
    }
}


void example_findAssociatedTokenAccount() {
    Serial.println("\n=== 🔹 findAssociatedTokenAccount() ===");

    String ata;
    if (solana.findAssociatedTokenAccount(toPubkeyBase58, tokenMintBase58, ata)) {
        Serial.print("Associated Token Account: ");
        Serial.println(ata);
    } else {
        Serial.println("❌ Failed to find ATA.");
    }
}

void example_signMessageRaw() {
    Serial.println("\n=== 🔹 signMessageRaw() ===");
 
    // Prepare message
    std::vector<uint8_t> msg = {'R', 'a', 'w', '_', 'T', 'e', 's', 't'};
    uint8_t signature[64];
 
    // Decode base58 private key into 64-byte raw vector
    uint8_t rawPrivKey[128];
    size_t privLen = sizeof(rawPrivKey);
    if (!base58Decode(PRIVATE_KEY_BASE58, rawPrivKey, privLen) || privLen < 64) {
        Serial.println("❌ Failed to decode private key from base58!");
        return;
    }
 
    std::vector<uint8_t> privKeyVec(rawPrivKey, rawPrivKey + 64);
 
    if (solana.signMessageRaw(msg, privKeyVec, signature)) {
        Serial.print("✅ Signature: ");
        for (int i = 0; i < 64; ++i) {
            if (signature[i] < 16) Serial.print("0");
            Serial.print(signature[i], HEX);
        }
        Serial.println();
    } else {
        Serial.println("❌ signMessageRaw failed.");
    }
}

void example_confirmTransaction() {
    Serial.println("\n=== 🔹 confirmTransaction() ===");

    String txSignature = "BASE58_SIGNATURE_STRING_HERE";

    if (solana.confirmTransaction(txSignature, 5000)) {
        Serial.println("✅ Transaction Confirmed.");
    } else {
        Serial.println("❌ Transaction NOT Confirmed.");
    }
}

void example_base64Encode() {
    Serial.println("\n=== 🔹 base64Encode() ===");

    const char* data = "IoTxChain Base64 Test!";
    String encoded = solana.base64Encode((const uint8_t*)data, strlen(data));
    Serial.print("Base64 Encoded: ");
    Serial.println(encoded);
}



void example_sendUnified() {
    String customData = "IoTxChain unified tx example!";
    bool result = solana.sendProgramDataTransaction(
        PRIVATE_KEY_BASE58,
        PUBLIC_KEY_BASE58,
        ProgramIdBase58,
        customData,
        7000
    );

    if (result) {
        Serial.println("✅ Unified tx success!");
    } else {
        Serial.println("❌ Unified tx failed.");
    }
}


void example_calculateDiscriminator() {
    Serial.println("\n=== 🔹 calculateDiscriminator() ===");

    String functionName = "update_temperature"; //
    std::vector<uint8_t> discriminator = solana.calculateDiscriminator(functionName.c_str());

    Serial.print("Discriminator for '" + functionName + "': ");
    for (uint8_t b : discriminator) {
        if (b < 16) Serial.print("0");
        Serial.print(b, HEX);
    }
    Serial.println();
}




void example_sendSol() {
    Serial.println("\n=== 🔹 sendSol() ===");

    uint64_t lamports = 1000000;  // 0.001 SOL
    bool result = solana.sendSol(
        PRIVATE_KEY_BASE58,
        PUBLIC_KEY_BASE58,
        toPubkeyBase58,
        lamports
    );

    if (result) {
        Serial.println("✅ SOL transaction sent!");
    } else {
        Serial.println("❌ Failed to send SOL transaction.");
    }
}


void example_base58ToPubkey() {
    Serial.println("\n=== 🔹 base58ToPubkey() ===");

    String pubkeyStr = PUBLIC_KEY_BASE58;

    std::vector<uint8_t> pubkeyVec = base58ToPubkey(pubkeyStr);

    if (pubkeyVec.size() != 32) {
        Serial.println("❌ Invalid public key!");
        return;
    }

    Serial.print("✅ Decoded Public Key (hex): ");
    for (uint8_t b : pubkeyVec) {
        if (b < 16) Serial.print("0");
        Serial.print(b, HEX);
    }
    Serial.println();
}

// Added generalized Anchor Instruction with PDA function
void example_sendAnchorInstructionWithPDA(
    const std::string& functionName,
    const std::vector<std::vector<uint8_t>>& customSeeds,
    const std::vector<uint8_t>& payload
) {
    Serial.println("\n=== 🔹 Anchor Instruction with PDA (Generic) ===");

    uint8_t privateKey[128];
    size_t privLen = sizeof(privateKey);
    if (!base58Decode(PRIVATE_KEY_BASE58, privateKey, privLen) || privLen < 64) {
        Serial.println("❌ Private key decode failed");
        return;
    }

    Pubkey authority = Pubkey::fromBase58(PUBLIC_KEY_BASE58);
    Keypair signer = Keypair::fromPrivateKey(privateKey);

    std::vector<uint8_t> programId = base58ToPubkey(ProgramIdBase58);

    Pubkey pda = Pubkey::fromBase58("BvqDoYkRZ6V3MA293AF3mYvakPyHrGcJ9ctS2Ax9BR28"); //PDA

    std::vector<uint8_t> discriminator = solana.calculateDiscriminator(functionName);
    std::vector<uint8_t> data = discriminator;
    data.insert(data.end(), payload.begin(), payload.end());

    Instruction ix(
        Pubkey{programId},
        functionName == "initialize" ? std::vector<AccountMeta>{
            AccountMeta::writable(pda, false),
            AccountMeta::writable(authority, true),
            AccountMeta{Pubkey::fromBase58("11111111111111111111111111111111"), false, false}
        } : std::vector<AccountMeta>{
            AccountMeta::writable(pda, false),
            AccountMeta::signer(authority)
        },
        data
    );

    Transaction tx;
    tx.fee_payer = authority;
    tx.recent_blockhash = solana.getLatestBlockhash();
    if (tx.recent_blockhash.isEmpty()) {
        Serial.println("❌ Failed to get blockhash!");
        return;
    }
    tx.add(ix);
    tx.sign({signer});
    String txBase64 = tx.serializeBase64();

    String txSig;
    if (solana.sendRawTransaction(txBase64, txSig)) {
        Serial.println("✅ Anchor tx sent! Signature: " + txSig);
    } else {
        Serial.println("❌ Anchor tx failed.");
    }
}

void example_callInitialize() {
    std::vector<std::vector<uint8_t>> seeds = {
        {'t','e','m','p','_','d','a','t','a'},
        base58ToPubkey(PUBLIC_KEY_BASE58)
    };

    std::vector<uint8_t> payload;  // no payload for initialize
    example_sendAnchorInstructionWithPDA("initialize", seeds, payload);
}

void example_callUpdateTemperature() {
    std::vector<std::vector<uint8_t>> seeds = {
        {'t','e','m','p','_','d','a','t','a'},
        base58ToPubkey(PUBLIC_KEY_BASE58)
    };

    int64_t temperature = 42;
    int64_t humidity = 55;  

    std::vector<uint8_t> payload;
    std::vector<uint8_t> tempEncoded = encodeU64LE((uint64_t)temperature);
    std::vector<uint8_t> humidityEncoded = encodeU64LE((uint64_t)humidity);

    payload.insert(payload.end(), tempEncoded.begin(), tempEncoded.end());
    payload.insert(payload.end(), humidityEncoded.begin(), humidityEncoded.end());
    
    example_sendAnchorInstructionWithPDA("update_temperature", seeds, payload);
}


void setup() {
    Serial.begin(115200);
    delay(1000);

    // Connect to WiFi
    Serial.println("Connecting to WiFi...");
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(1000);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected!");


    Serial.println("example_sendSol");
    example_sendSol();

    Serial.println("example_base58ToPubkey");
    example_base58ToPubkey();

    Serial.println("example_findAssociatedTokenAccount");
    example_findAssociatedTokenAccount();

    Serial.println("example_signMessageRaw");
    example_signMessageRaw();

    Serial.println("example_confirmTransaction");
    example_confirmTransaction();

    Serial.println("example_base64Encode");
    example_base64Encode();

    Serial.println("example_calculateDiscriminator");
    example_calculateDiscriminator();

    Serial.println("example_sendUnified");
    example_sendUnified();


    Serial.println("example_getSolBalance");
    example_getSolBalance();

    Serial.println("example_getSplTokenBalance");
    example_getSplTokenBalance();
    
    Serial.println("example_getTokenDecimals");
    example_getTokenDecimals();

    Serial.println("example_getLatestBlockhash");
    example_getLatestBlockhash();

    Serial.println("example_getBlockHeight");
    example_getBlockHeight();

    Serial.println("example_getEpochInfo");
    example_getEpochInfo();

    Serial.println("example_signMessageFromBase58");
    example_signMessageFromBase58();

    Serial.println("example_callInitialize");
    example_callInitialize();
    
    delay(5000);
    
    Serial.println("example_callUpdateTemperature");
    example_callUpdateTemperature();
}

void loop() {
    // Nothing here
}


