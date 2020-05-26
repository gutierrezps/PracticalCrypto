/**
 * @file PracticalCrypto.cpp
 * @author Gutierrez PS (https://github.com/gutierrezps)
 * @brief Library for easy encryption and decryption of Strings in ESP8266 Arduino core.
 * @version 0.1.0
 * @date 2020-05-25
 * 
 */
#include <Arduino.h>
#include <bearssl/bearssl_block.h>
#include <bearssl/bearssl_hmac.h>

#include "PracticalCrypto.h"

#define BLK_SZ   br_aes_big_BLOCK_SIZE


bool PracticalCrypto::setKey(String key)
{
    if (key.length() != 64) {
        key_ = "";
        return false;
    }

    key_ = key;

    key_.toCharArray((char*)staticIv_, 17, 0);
    key_.toCharArray((char*)ivKey_, 17, 16);
    key_.toCharArray((char*)dataKey_, 17, 32);
    key_.toCharArray((char*)hashKey_, 17, 48);

    return true;
}



String PracticalCrypto::generateKey()
{
    String key = "";
    for (uint8_t i = 0; i < 64; ++i) {
        key += (char)(32 + secureRandom(90));
    }
    return key;
}



/**
 * Encrypts the provided plaintext String. The following steps are done:
 * 
 * 1. Plaintext is padded to be evenly divided into blocks of BLK_SZ bytes
 *      If it's already evenly divided, a whole padding block is added,
 *      The value of the byte used to pad is the number of padding bytes needed.
 * 2. A random initialization vector (IV) is generated
 * 3. The random IV is encryted (AES128-CBC) using ivKey_ and staticIv_
 * 4. The data is encrypted (AES128-CBC) using dataKey_ and the random IV
 * 5. The hash (HMAC-SHA1) of encrypted IV + encrypted data is calculated,
 *      using hashKey_ and following the Encrypt-then-MAC approach.
 * 6. The output String (ciphertext) is formed by concatenating hex strings of
 *      encrypted IV, encrypted data and hash.
 * 
 * @param plaintext     String to be encrypted
 * @return String       ciphertext
 */
String PracticalCrypto::encrypt(String plaintext)
{
    if (key_.length() == 0) {
        lastStatus_ = InvalidKey;
        return "";
    }

    if (plaintext.length() > kMaxDataLength_) {
        lastStatus_ = PlaintextTooLong;
        return "";
    }

    if (!dataBuffer_) {
        lastStatus_ = BufferAllocationFailed;
        return "";
    }

    uint16_t i = 0;

    // dataBuffer_ will turn into the encrypted plaintext later
    memcpy(dataBuffer_, plaintext.c_str(), plaintext.length());

    // number of blocks required for data is rounded up if division has decimals,
    // otherwise a full padding block is added if the division is even
    uint8_t dataBlocksQty = plaintext.length() / BLK_SZ + 1;

    // add padding to dataBuffer_
    uint8_t dataPadding = dataBlocksQty * BLK_SZ - plaintext.length();
    const uint16_t paddingStart = dataBlocksQty * BLK_SZ - dataPadding;
    for (i = paddingStart; i < dataBlocksQty * BLK_SZ; ++i) {
        dataBuffer_[i] = dataPadding;
    }

    // generating a random IV of printable chars (ASCII 32-122)
    uint8_t iv[BLK_SZ] = {0};
    for (i = 0; i < BLK_SZ-1; ++i) {
        iv[i] = 32 + secureRandom(90);
    }

    // manual padding is added in order to encrypted IV be exactly BLK_SZ bytes;
    // otherwise, when decrypting in PHP a whole padding block would be expected
    iv[BLK_SZ-1] = 1;

    yield();    // reset watchdog

    // encryption context
    br_aes_big_cbcenc_keys encCtx;

    // encrypt IV
    uint8_t staticIv[BLK_SZ] = {0};
    memcpy(staticIv, staticIv_, BLK_SZ);      // copy to local, modifiable variable

    uint8_t ivCipher[BLK_SZ] = {0};
    memcpy(ivCipher, iv, BLK_SZ);

    br_aes_big_cbcenc_init(&encCtx, ivKey_, BLK_SZ);
    br_aes_big_cbcenc_run(&encCtx, staticIv, ivCipher, BLK_SZ);

    yield();    // reset watchdog

    // reset the encryption context and encrypt the data
    br_aes_big_cbcenc_init(&encCtx, dataKey_, BLK_SZ);
    br_aes_big_cbcenc_run(&encCtx, iv, dataBuffer_, dataBlocksQty * BLK_SZ);

    yield();

    // calculate hash

    // contexts
    br_hmac_key_context hashKc;
    br_hmac_context hashCtx;

    // initialize key context with the SHA1 algorithm, the given key and its length
    br_hmac_key_init(&hashKc, &br_sha1_vtable, hashKey_, BLK_SZ);

    // initialize hashing context, setting the output size
    br_hmac_init(&hashCtx, &hashKc, br_sha1_SIZE);

    // hash encrypted IV and encrypted data
    br_hmac_update(&hashCtx, ivCipher, BLK_SZ);
    br_hmac_update(&hashCtx, dataBuffer_, dataBlocksQty * BLK_SZ);

    yield();

    // get the output hash
    uint8_t hash[br_sha1_SIZE] = {0};
    br_hmac_out(&hashCtx, hash);

    // convert to hex string and concatenate
    String ciphertext = arrayToHexString(ivCipher, BLK_SZ);
    ciphertext += arrayToHexString(dataBuffer_, dataBlocksQty * BLK_SZ);
    ciphertext += arrayToHexString(hash, br_sha1_SIZE);

    lastStatus_ = Ok;

    return ciphertext;
}



/**
 * Decrypts the provided ciphertext String. The following steps are done:
 * 
 * 1. Ciphertext is validated and converted to byte arrays.
 * 2. Hash of encrypted IV + encrypted data is calculated using hashKey_
 *      and compared with hash extracted from ciphertext
 * 3. IV is decrypted using ivKey_ and staticIv_
 * 4. Data is decrypted using IV and dataKey_
 * 5. Output string (plaintext) is generated from data, excluding padding bytes
 * 
 * @param ciphertext    String to be decrypted
 * @return String       plaintext data
 */
String PracticalCrypto::decrypt(String ciphertext)
{
    if (key_.length() == 0) {
        lastStatus_ = InvalidKey;
        return "";
    }

    if (!dataBuffer_) {
        lastStatus_ = BufferAllocationFailed;
        return "";
    }

    // minimum ciphertext hex string length:
    // iv + min plaintext length (padded) + sha1 output length
    const uint16_t minCiphertextLength = (16 + 16 + 20)*2;

    if (ciphertext.length() < minCiphertextLength || ciphertext.length() % 2 != 0) {
        lastStatus_ = InvalidCiphertextLength;
        return "";
    }

    // maximum ciphertext hex string length:
    // iv + max plaintext length (padded) + sha1 output length
    const uint16_t maxCiphertextLength = (16 + (kMaxDataLength_ + 16) + 20)*2;

    if (ciphertext.length() > maxCiphertextLength) {
        lastStatus_ = CiphertextTooLong;
        return "";
    }

    const uint16_t ivEnd = BLK_SZ*2;
    const uint16_t hashStart = ciphertext.length() - br_sha1_SIZE*2;

    // second param of substring is end index, and it's exclusive
    String ivHex = ciphertext.substring(0, ivEnd);
    String dataHex = ciphertext.substring(ivEnd, hashStart);
    String hashHex = ciphertext.substring(hashStart);

    uint16_t converted = 0;
    const uint16_t dataLength = dataHex.length() / 2;

    uint8_t ivCipher[BLK_SZ] = {0};
    uint8_t hashCipher[br_sha1_SIZE] = {0};

    converted = hexStringToArray(ivHex, ivCipher, BLK_SZ);
    if (converted == 0) {
        // last status already set
        return "";
    }

    converted = hexStringToArray(dataHex, dataBuffer_, dataLength);
    if (converted == 0) {
        // last status already set
        return "";
    }

    converted = hexStringToArray(hashHex, hashCipher, br_sha1_SIZE);
    if (converted == 0) {
        // last status already set
        return "";
    }

    yield();

    // calculate hash

    // contexts
    br_hmac_key_context hashKc;
    br_hmac_context hashCtx;

    // initialize key context with the SHA1 algorithm, the given key and its length
    br_hmac_key_init(&hashKc, &br_sha1_vtable, hashKey_, BLK_SZ);

    // initialize hashing context, setting the output size
    br_hmac_init(&hashCtx, &hashKc, br_sha1_SIZE);

    // hash encrypted IV and encrypted data
    br_hmac_update(&hashCtx, ivCipher, BLK_SZ);
    br_hmac_update(&hashCtx, dataBuffer_, dataLength);

    yield();

    // get the hash value
    uint8_t hashExpected[br_sha1_SIZE] = {0};
    br_hmac_out(&hashCtx, hashExpected);

    if (memcmp(hashExpected, hashCipher, br_sha1_SIZE) != 0) {
        lastStatus_ = HashMismatch;
        return "";
    }

    // decryption context
    br_aes_big_cbcdec_keys decCtx;

    uint8_t staticIv[BLK_SZ] = {0};
    memcpy(staticIv, staticIv_, BLK_SZ);

    // decrypt IV
    br_aes_big_cbcdec_init(&decCtx, ivKey_, BLK_SZ);
    br_aes_big_cbcdec_run(&decCtx, staticIv, ivCipher, BLK_SZ);

    yield();

    // decrypt data
    br_aes_big_cbcdec_init(&decCtx, dataKey_, BLK_SZ);
    br_aes_big_cbcdec_run(&decCtx, ivCipher, dataBuffer_, dataLength);

    yield();
    
    // get number of padding bytes used
    const uint8_t dataPadding = dataBuffer_[dataLength - 1];

    // insert a null char to terminate the string
    dataBuffer_[dataLength - dataPadding] = 0;

    lastStatus_ = Ok;

    return String((char*) dataBuffer_);
}



inline int8_t hexToByte(char hex)
{
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    }
    else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    }
    else if (hex >= 'A' && hex <= 'F') {
        return hex - 'A' + 10;
    }
    
    return -1;
}



uint16_t PracticalCrypto::hexStringToArray(
    String input,
    uint8_t *output,
    uint16_t capacity)
{
    uint8_t val = 0;
    uint16_t i = 0;
    char ch = 0;
    uint16_t bytesQty = input.length() / 2;

    if (input.length() % 2 != 0) {
        lastStatus_ = InvalidHexString;
        return 0;
    }

    if (bytesQty > capacity) {
        lastStatus_ = HexStringTooLong;
        return 0;
    }

    for (i = 0; i < bytesQty; ++i) {
        val = 0;
        ch = input.charAt(i * 2);

        if (hexToByte(ch) < 0) {
            lastStatus_ = InvalidHexString;
            return 0;
        }
        val += hexToByte(ch);

        val *= 16;

        ch = input.charAt(i * 2 + 1);
        if (hexToByte(ch) < 0) {
            lastStatus_ = InvalidHexString;
            return 0;
        }
        val += hexToByte(ch);

        output[i] = val;
    }

    lastStatus_ = Ok;

    return i;
}



String PracticalCrypto::arrayToHexString(uint8_t *input, uint16_t len)
{
    String ret = "";

    for (uint16_t i = 0; i < len; ++i) {
        char ch = (input[i] >> 4) & 0x0F;
        if (ch < 10) ch += '0';
        else ch += 'A' - 10;
        ret += ch;

        ch = input[i] & 0x0F;
        if (ch < 10) ch += '0';
        else ch += 'A' - 10;
        ret += ch;
    }

    return ret;
}

#undef BLK_SZ
