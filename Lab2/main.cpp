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
    using namespace std;
    
    string key;
    cout << "Input Secret Key (16, 24, or 32 bytes):\n";
    getline(cin, key);

    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        std::cerr << "Invalid key length! Must be 16, 24, or 32 bytes.\n";
        return;
    }

    string iv;
    cout << "Input Initial Vector (16 bytes):\n";
    getline(cin, iv);

    if (iv.size() != 16) {
        std::cerr << "Initial Vector IV length must be 16 bytes.\n";
        return;
    }

    vector<uint8_t> key_bytes(key.begin(), key.end());
    vector<uint8_t> iv_bytes(iv.begin(), iv.end());

    try {
        Modes aes_mode(key_bytes, iv_bytes);
        cout << "Do you want to encrypt or decrypt (e/d)? ";
        char choice;
        cin >> choice;
        cin.ignore();

        auto start = chrono::steady_clock::now();

        if (choice == 'e' || choice == 'E') {
            string plaintext;
            cout << "Input plaintext:\n";
            getline(cin, plaintext);

            vector<uint8_t> cipher = aes_mode.cbc_encrypt(plaintext);

            cout << "Ciphertext (hex):\n";
            for (uint8_t c : cipher) {
                cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
            }
            cout << std::dec << std::endl;

            auto end = chrono::steady_clock::now();
            auto programDuration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
            cout << "Encryption time: " << programDuration << " milliseconds" << endl;
        } else if (choice == 'd' || choice == 'D') {
            string ciphertext_hex;
            cout << "Input Ciphertext (hex):\n";
            getline(cin, ciphertext_hex);

            vector<uint8_t> ciphertext;
            if (ciphertext_hex.length() % 2 != 0) {
                std::cerr << "Invalid hex string length!\n";
                return;
            }

            for (size_t i = 0; i < ciphertext_hex.length(); i += 2) {
                string byte_string = ciphertext_hex.substr(i, 2);
                try {
                    auto byte = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
                    ciphertext.push_back(byte);
                } catch (const std::exception& e) {
                    std::cerr << "Invalid hex format!\n";
                    return;
                }
            }

            string recovered_text = aes_mode.cbc_decrypt(ciphertext);
            cout << "Recovered text:\n" << recovered_text << std::endl;

            auto end = chrono::steady_clock::now();
            auto programDuration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
            cout << "Decryption time: " << programDuration << " milliseconds" << endl;

        } else {
            cout << "Invalid command. Please enter 'e' or 'd'.\n";
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

    aes_mode_test();

    return 0;
}