#include "Modes.h"
#include <iostream>
#include <iomanip>
#include <bitset>
#include <chrono>

using namespace std;

#ifdef _WIN32
#include <windows.h>
#elif defined(__linux__) || defined(__unix__)
#include <locale.h>
#endif

string message_to_bin(const string& message) {
    string binary_message;
    for (unsigned char byte : message) {
        binary_message += bitset<8>(byte).to_string();
    }
    return binary_message;
}

void aes_mode_test() {
    string key;
    cout << "Input Secret Key (16, 24, or 32 bytes):\n";
    getline(cin, key);

    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        cerr << "Invalid key length! Must be 16, 24, or 32 bytes.\n";
        return;
    }

    string iv;
    cout << "Input Initial Vector (16 bytes):\n";
    getline(cin, iv);

    if (iv.size() != 16) {
        cerr << "Initial Vector IV length must be 16 bytes.\n";
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

        if (choice == 'e' || choice == 'E') {
            string plaintext;
            cout << "Input plaintext:\n";
            getline(cin, plaintext);

            vector<uint8_t> cipher = aes_mode.cbc_encrypt(plaintext);

            cout << "Ciphertext (hex):\n";
            for (uint8_t c : cipher) {
                cout << hex << setw(2) << setfill('0') << static_cast<int>(c);
            }
            cout << dec << endl;
        } else if (choice == 'd' || choice == 'D') {
            string ciphertext_hex;
            cout << "Input Ciphertext (hex):\n";
            getline(cin, ciphertext_hex);

            vector<uint8_t> ciphertext;
            if (ciphertext_hex.length() % 2 != 0) {
                cerr << "Invalid hex string length!\n";
                return;
            }

            for (size_t i = 0; i < ciphertext_hex.length(); i += 2) {
                string byte_string = ciphertext_hex.substr(i, 2);
                try {
                    auto byte = static_cast<uint8_t>(stoi(byte_string, nullptr, 16));
                    ciphertext.push_back(byte);
                } catch (const exception& e) {
                    cerr << "Invalid hex format!\n";
                    return;
                }
            }

            string recovered_text = aes_mode.cbc_decrypt(ciphertext);
            cout << "Recovered text:\n" << recovered_text << endl;
        } else {
            cout << "Invalid command. Please enter 'e' or 'd'.\n";
        }
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
    }
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#else
    setlocale(LC_ALL, "en_US.UTF-8");
#endif
    auto start = chrono::high_resolution_clock::now();
    aes_mode_test();
    auto end = chrono::high_resolution_clock::now();
    auto programDuration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    cout << programDuration << " milliseconds" << endl;
    return 0;
}