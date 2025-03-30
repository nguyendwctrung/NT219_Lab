#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

class AES
{
private:
    std::vector<uint8_t> key;
    int key_length;
    std::vector<std::vector<uint8_t>> round_keys;

    static const uint8_t sbox[256];     // S-box for AES
    static const uint8_t inv_sbox[256]; // Inverse S-box for AES

    static const std::vector<std::vector<uint8_t>> rcon; // Round constants for AES

    std::vector<uint8_t> sub_word(const std::vector<uint8_t> &word);
    std::vector<uint8_t> rot_word(const std::vector<uint8_t> &word);

    std::vector<std::vector<uint8_t>> key_expansion(const std::vector<uint8_t> &key, int length);
    std::vector<std::vector<uint8_t>> key_expansion_128();
    std::vector<std::vector<uint8_t>> key_expansion_192();
    std::vector<std::vector<uint8_t>> key_expansion_256();

    std::vector<std::vector<uint8_t>> sub_bytes(std::vector<std::vector<uint8_t>> &state);
    std::vector<std::vector<uint8_t>> shift_rows(std::vector<std::vector<uint8_t>> &state);
    std::vector<std::vector<uint8_t>> mix_columns(std::vector<std::vector<uint8_t>> &state);
    std::vector<std::vector<uint8_t>> add_round_key(std::vector<std::vector<uint8_t>> &state, int roundNumber);

    std::vector<std::vector<uint8_t>> inv_sub_bytes(std::vector<std::vector<uint8_t>> &state);
    std::vector<std::vector<uint8_t>> inv_shift_rows(std::vector<std::vector<uint8_t>> &state);
    std::vector<std::vector<uint8_t>> inv_mix_columns(std::vector<std::vector<uint8_t>> &state);

    uint8_t gmul(uint8_t a, uint8_t b);

public:
    AES(const std::vector<uint8_t> &key, int key_length);
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext);
};