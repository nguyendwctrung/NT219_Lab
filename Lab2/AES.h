#pragma once
#include <vector>
#include <cstdint>

class AES {
private:
    std::vector<std::vector<uint8_t>> round_keys;
    std::vector<uint8_t> key;
    uint8_t key_length;

    // Các bảng tĩnh
    const std::vector<uint8_t> S_BOX;
    const std::vector<uint8_t> INV_S_BOX;
    const std::vector<std::vector<uint8_t>> RCON;

    // Các hàm mở rộng khóa
    std::vector<uint8_t> sub_word(const std::vector<uint8_t>& word);
    static std::vector<uint8_t> rot_word(std::vector<uint8_t> word);
    std::vector<std::vector<uint8_t>> key_expansion_128();
    std::vector<std::vector<uint8_t>> key_expansion_192();
    std::vector<std::vector<uint8_t>> key_expansion_256();

    // Các hàm xử lý trạng thái
    std::vector<std::vector<uint8_t>> sub_bytes(std::vector<std::vector<uint8_t>> state);
    static std::vector<std::vector<uint8_t>> shift_rows(std::vector<std::vector<uint8_t>> state);
    static std::vector<std::vector<uint8_t>> mix_columns(std::vector<std::vector<uint8_t>> state);
    std::vector<std::vector<uint8_t>> inv_sub_bytes(std::vector<std::vector<uint8_t>> state);
    static std::vector<std::vector<uint8_t>> inv_shift_rows(std::vector<std::vector<uint8_t>> state);
    static std::vector<std::vector<uint8_t>> inv_mix_columns(std::vector<std::vector<uint8_t>> state);
    std::vector<std::vector<uint8_t>> add_round_key(std::vector<std::vector<uint8_t>> state, uint8_t round_number);

public:
    AES(const std::vector<uint8_t>& key, uint8_t key_length);
    std::vector<std::vector<uint8_t>> key_expansion(std::vector<uint8_t> key, uint8_t length);
    std::vector<uint8_t> encrypt(std::vector<uint8_t> data);
    std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext);
};
