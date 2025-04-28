#pragma once

#include "AES.h"
#include <vector>
#include <string>
#include <cstdint>

class Modes {
private:
    AES aes;
    std::vector<uint8_t> iv;

public:
    Modes(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    static std::vector<uint8_t> utf8_to_bytes(const std::string& utf8_str);
    static std::string bytes_to_utf8(const std::vector<uint8_t>& bytes_data);
    static std::vector<uint8_t> binary_to_bytes(const std::string& binary_str);
    static std::string bytes_to_binary(const std::vector<uint8_t>& bytes_data);
    static std::vector<uint8_t> pkcs7_padding(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> pkcs7_unpadding(const std::vector<uint8_t>& data);
    static std::string to_hex(const std::vector<uint8_t>& data);
    std::vector<uint8_t> cbc_encrypt(const std::string& plaintext);
    std::string cbc_decrypt(const std::vector<uint8_t>& ciphertext);
};
