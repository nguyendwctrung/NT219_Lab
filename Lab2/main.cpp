#include "Modes.h"
#include <iostream>
#include <iomanip>
#include <bitset>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#elif defined(__linux__) || defined(__unix__)
#include <locale.h>
#endif

std::string message_to_bin(const std::string& message) {
    std::string binary_message;
    for (unsigned char byte : message) {
        binary_message += std::bitset<8>(byte).to_string();
    }
    return binary_message;
}

void aes_mode_test() {
    std::string key;
    std::cout << "Input Secret Key (16, 24, or 32 bytes):\n";
    std::getline(std::cin, key);

    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        std::cerr << "Invalid key length! Must be 16, 24, or 32 bytes.\n";
        return;
    }

    std::string iv;
    std::cout << "Input Initial Vector (16 bytes):\n";
    std::getline(std::cin, iv);

    if (iv.size() != 16) {
        std::cerr << "Initial Vector IV length must be 16 bytes.\n";
        return;
    }

    std::vector<uint8_t> key_bytes(key.begin(), key.end());
    std::vector<uint8_t> iv_bytes(iv.begin(), iv.end());

    try {
        Modes aes_mode(key_bytes, iv_bytes);
        std::cout << "Do you want to encrypt or decrypt (e/d)? ";
        char choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 'e' || choice == 'E') {
            std::string plaintext;
            std::cout << "Input plaintext:\n";
            std::getline(std::cin, plaintext);

            std::vector<uint8_t> cipher = aes_mode.cbc_encrypt(plaintext);

            std::cout << "Ciphertext (hex):\n";
            for (uint8_t c : cipher) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
            }
            std::cout << std::dec << std::endl;
        } else if (choice == 'd' || choice == 'D') {
            std::string ciphertext_hex;
            std::cout << "Input Ciphertext (hex):\n";
            std::getline(std::cin, ciphertext_hex);

            std::vector<uint8_t> ciphertext;
            if (ciphertext_hex.length() % 2 != 0) {
                std::cerr << "Invalid hex string length!\n";
                return;
            }

            for (size_t i = 0; i < ciphertext_hex.length(); i += 2) {
                std::string byte_string = ciphertext_hex.substr(i, 2);
                try {
                    auto byte = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
                    ciphertext.push_back(byte);
                } catch (const std::exception& e) {
                    std::cerr << "Invalid hex format!\n";
                    return;
                }
            }

            std::string recovered_text = aes_mode.cbc_decrypt(ciphertext);
            std::cout << "Recovered text:\n" << recovered_text << std::endl;
        } else {
            std::cout << "Invalid command. Please enter 'e' or 'd'.\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#else
    setlocale(LC_ALL, "en_US.UTF-8");
#endif
    auto start = std::chrono::high_resolution_clock::now();
    aes_mode_test();
    auto end = std::chrono::high_resolution_clock::now();
    return 0;
}