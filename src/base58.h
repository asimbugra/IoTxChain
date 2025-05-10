#ifndef BASE58_H
#define BASE58_H

#include <Arduino.h>

/**
 * Base58 Encode:
 *   data: the byte array to be encoded
 *   len : length of the byte array (in bytes)
 * Returns: String encoded in Base58
 */
String base58Encode(const uint8_t* data, size_t len);

/**
 * Base58 Decode:
 *   b58   : input string encoded in Base58
 *   output: buffer to store the decoded raw bytes
 *   outLen: initially holds the capacity of the output buffer;
 *           on success, it will be updated to the actual number of decoded bytes
 * Returns: true if decoding is successful, false otherwise
 */
bool base58Decode(const String& b58, uint8_t* output, size_t& outLen);

#endif
