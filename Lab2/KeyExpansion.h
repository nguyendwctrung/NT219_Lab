#pragma once

#include <vector>
#include <cstdint>

class KeyExpansion
{
private:
    std::vector<uint8_t> key;
    static const uint8_t sbox[256];   // S-box for AES
    static const uint8_t rcon[10][4]; // Rcon array for AES key expansion
    std::vector<uint8_t> subWord(const std::vector<uint8_t> &word);
    std::vector<uint8_t> rotWord(const std::vector<uint8_t> &word);

public:
    KeyExpansion(const std::vector<uint8_t> &key);
    ~KeyExpansion();
    std::vector<std::vector<uint8_t>> KeyExpansion128(const std::vector<uint8_t> &key);
    std::vector<std::vector<uint8_t>> KeyExpansion192(const std::vector<uint8_t> &key);
    std::vector<std::vector<uint8_t>> KeyExpansion256(const std::vector<uint8_t> &key);
};