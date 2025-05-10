#include "base58.h"
#include <vector>
#include <Arduino.h>

/**
 * Base58 alphabet used in Bitcoin/Monero/Solana, etc.
 * Characters like 0, O, I, and l are omitted to avoid visual ambiguity.
 */
static const char *BASE58_ALPHABET = 
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Base58 Encode
 */
String base58Encode(const uint8_t* data, size_t len) {
    // Special case: empty input
    if (!data || len == 0) {
        return "";
    }

    // Count leading zero bytes (each 0x00 maps to '1')
    int zeroCount = 0;
    while (zeroCount < (int)len && data[zeroCount] == 0) {
        zeroCount++;
    }

    // Convert data to base58 using a simple approach treating it as a big integer
    std::vector<unsigned char> buf(data, data + len);

    int startIndex = zeroCount;
    std::string encoded;
    encoded.reserve(len * 2);

    // Perform division by 58 and keep the remainders
    while (startIndex < (int)buf.size()) {
        int carry = 0;
        for (int i = startIndex; i < (int)buf.size(); i++) {
            int val = ((int)buf[i] & 0xFF) + (carry << 8);
            buf[i] = (unsigned char)(val / 58);
            carry = val % 58;
        }

        if (buf[startIndex] == 0) {
            startIndex++;
        }
        encoded.push_back(BASE58_ALPHABET[carry]);
    }

    // Add '1' for each leading zero byte
    for (int i = 0; i < zeroCount; i++) {
        encoded.push_back('1');
    }

    // Reverse the result to obtain the correct base58 string
    std::reverse(encoded.begin(), encoded.end());

    return String(encoded.c_str());
}

/**
 * Base58 Decode
 *  - Converts base58 string to raw byte array
 *  - Useful for typical use cases like Solana public keys (32 bytes)
 *  - outLen initially holds the buffer capacity, then updated with actual length
 */
bool base58Decode(const String& b58, uint8_t* output, size_t& outLen) {
    if (b58.length() == 0) {
        outLen = 0;
        return true;
    }

    // Lookup table for fast base58 character-to-index mapping
    // Invalid characters are mapped to -1
    static int8_t map[128];
    static bool mapInitialized = false;
    if (!mapInitialized) {
        memset(map, -1, sizeof(map));
        for (int i = 0; i < 58; i++) {
            char c = BASE58_ALPHABET[i];
            map[(int)c] = i;
        }
        mapInitialized = true;
    }

    // Count leading '1's -> represent zero bytes
    int zeroCount = 0;
    while (zeroCount < (int)b58.length() && b58[zeroCount] == '1') {
        zeroCount++;
    }

    // Convert base58 string to base256 using big integer logic
    std::vector<uint8_t> temp((b58.length() - zeroCount) * 733 / 1000 + 1); 
    // log(58) / log(256) ≈ 0.73

    for (int i = zeroCount; i < (int)b58.length(); i++) {
        int c = (uint8_t)b58[i];
        if (c < 0 || c >= 128 || map[c] == -1) {
            // Invalid character
            return false;
        }
        int carry = map[c];
        for (int j = (int)temp.size() - 1; j >= 0; j--) {
            carry += 58 * temp[j];
            temp[j] = carry % 256;
            carry /= 256;
        }
        if (carry != 0) {
            // Overflow, input too large
            return false;
        }
    }

    // Skip leading zero bytes in the result
    int skip = 0;
    while (skip < (int)temp.size() && temp[skip] == 0) {
        skip++;
    }

    // Total decoded length = leading zeros + meaningful bytes
    size_t decodedLen = zeroCount + (temp.size() - skip);

    if (decodedLen > outLen) {
        // Provided buffer too small
        return false;
    }

    // Fill result: first zeroCount zero bytes
    memset(output, 0, zeroCount);
    // Copy remaining bytes from temp
    for (size_t i = zeroCount; i < decodedLen; i++) {
        output[i] = temp[skip++];
    }

    outLen = decodedLen;
    return true;
}
