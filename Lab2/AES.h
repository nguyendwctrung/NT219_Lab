#pragma once

#include <string>
#include <vector>
#include <cstdint>

class AES
{
private:
    // Expand the key into round keys
    void keyExpansion(const std::vector<uint8_t>& key, std::vector<uint8_t>& roundKeys);

    // Add the round key to the state
    void addRoundKey(uint8_t state[4][4], int round);

    // Combine transformation during encryption
    void subBytes(uint8_t state[4][4]);
    void shiftRows(uint8_t state[4][4]);
    void mixColumns(uint8_t state[4][4]);

    // Combine transformation during decryption
    void invSubBytes(uint8_t state[4][4]);
    void invShiftRows(uint8_t state[4][4]);
    void invMixColumns(uint8_t state[4][4]);

    // Helper functions used in mixColumns
    static uint8_t xtime(uint8_t x);
    static uint8_t multiply(uint8_t a, uint8_t b);

    // The expand round keys (176 bytes for AES-128)
    std::vector<uint8_t> roundKeys;
public:
    // AES expects a 16-byte key for AES-128
    AES(const std::vector<uint8_t>& key);
    ~AES();

    // Encrypt and decrypt a block of 16 bytes
    void encryptBlock(uint8_t input[16], uint8_t output[16]);
    void decryptBlock(uint8_t input[16], uint8_t output[16]);
};