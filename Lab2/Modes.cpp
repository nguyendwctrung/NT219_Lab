#include "Modes.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <locale>
#include <codecvt>
#include <bitset>

Modes::Modes(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv)
        : aes(key, static_cast<int>(key.size())), iv(iv) {
    int key_length = static_cast<int>(key.size() * 8);
    if (key_length != 128 && key_length != 192 && key_length != 256) {
        throw std::invalid_argument("Invalid key length. Supported lengths are 128, 192, and 256 bits.");
    }
}

std::vector<uint8_t> Modes::utf8_to_bytes(const std::string& utf8_str) {
    return std::vector<uint8_t>(utf8_str.begin(), utf8_str.end());
}

std::string Modes::bytes_to_utf8(const std::vector<uint8_t>& bytes_data) {
    std::locale loc(std::locale(), new std::codecvt_utf8<wchar_t>);
    std::string result(bytes_data.begin(), bytes_data.end());
    return result;
}

std::vector<uint8_t> Modes::binary_to_bytes(const std::string& binary_str) {
    std::string padded_binary_str = binary_str;
    int padding_length = 8 - (binary_str.size() % 8);
    padded_binary_str += '1' + std::string(padding_length - 1, '0');
    std::vector<uint8_t> bytes((padded_binary_str.size() + 7) / 8);
    for (size_t i = 0; i < padded_binary_str.size(); i += 8) {
        bytes[i / 8] = std::bitset<8>(padded_binary_str.substr(i, 8)).to_ulong();
    }
    return bytes;
}

std::string Modes::bytes_to_binary(const std::vector<uint8_t>& bytes_data) {
    std::string binary_str;
    for (uint8_t byte : bytes_data) {
        binary_str += std::bitset<8>(byte).to_string();
    }
    size_t last_one_index = binary_str.rfind('1');
    return "0b" + binary_str.substr(0, last_one_index);
}

std::vector<uint8_t> Modes::pkcs7_padding(const std::vector<uint8_t>& data) {
    size_t padding_length = 16 - (data.size() % 16);
    std::vector<uint8_t> padded_data = data;
    padded_data.insert(padded_data.end(), padding_length, padding_length);
    return padded_data;
}

std::vector<uint8_t> Modes::pkcs7_unpadding(const std::vector<uint8_t>& data) {
    size_t padding_length = data.back();
    return std::vector<uint8_t>(data.begin(), data.end() - padding_length);
}

std::string Modes::to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<uint8_t> Modes::cbc_encrypt(const std::string& plaintext) {
    std::vector<uint8_t> padded_data = pkcs7_padding(utf8_to_bytes(plaintext));
    std::vector<uint8_t> encrypted_blocks;
    std::vector<uint8_t> previous_block = iv;

    for (size_t i = 0; i < padded_data.size(); i += 16) {
        std::vector<uint8_t> block(padded_data.begin() + i, padded_data.begin() + i + 16);
        for (size_t j = 0; j < 16; ++j) {
            block[j] ^= previous_block[j];
        }
        std::vector<uint8_t> encrypted_block = aes.encrypt(block);
        encrypted_blocks.insert(encrypted_blocks.end(), encrypted_block.begin(), encrypted_block.end());
        previous_block = encrypted_block;
    }

    std::vector<uint8_t> result = iv;
    result.insert(result.end(), encrypted_blocks.begin(), encrypted_blocks.end());
    return result;
}

std::string Modes::cbc_decrypt(const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() % 16 != 0) {
        throw std::invalid_argument("Ciphertext length must be a multiple of 16 bytes for CBC mode.");
    }

    std::vector<uint8_t> decrypted_blocks;
    std::vector<uint8_t> previous_block(ciphertext.begin(), ciphertext.begin() + 16);
    std::vector<uint8_t> encrypted_data(ciphertext.begin() + 16, ciphertext.end());

    for (size_t i = 0; i < encrypted_data.size(); i += 16) {
        std::vector<uint8_t> block(encrypted_data.begin() + i, encrypted_data.begin() + i + 16);
        std::vector<uint8_t> decrypted_block = aes.decrypt(block);
        for (size_t j = 0; j < 16; ++j) {
            decrypted_block[j] ^= previous_block[j];
        }
        decrypted_blocks.insert(decrypted_blocks.end(), decrypted_block.begin(), decrypted_block.end());
        previous_block = block;
    }

    std::vector<uint8_t> unpadded_data = pkcs7_unpadding(decrypted_blocks);
    return bytes_to_utf8(unpadded_data);
}