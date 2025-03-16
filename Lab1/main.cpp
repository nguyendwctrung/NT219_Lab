#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdexcept>
#include <cstring>
#include <windows.h>
#include <fcntl.h>
#include <chrono>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/xts.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>

// Avoid using namespace for CryptoPP to prevent ambiguity (e.g. for byte)
using namespace std;

enum CipherAlgorithm
{
    ALGO_DES,
    ALGO_AES
};

void GenerateRandom(CryptoPP::byte *buffer, size_t size)
{
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(buffer, size);
}

string ReadFromFile(const string &fileName)
{
    ifstream file(fileName, ios::binary);
    if (!file)
        throw runtime_error("Could not open file: " + fileName);
    stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

void WriteToFile(const string &fileName, const string &data)
{
    ofstream file(fileName, ios::binary);
    if (!file)
        throw runtime_error("Could not write to file: " + fileName);
    file << data;
}

string StringToHex(const string &input)
{
    string encoded;
    CryptoPP::StringSource ss(input, true,
                              new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));
    return encoded;
}

string Encrypt(const string &plaintext, const CryptoPP::SecByteBlock &key,
               const CryptoPP::SecByteBlock &iv, CipherAlgorithm algo, int modeOption)
{
    string ciphertext;
    try
    {
        switch (algo)
        {
        case ALGO_AES:
        {
            switch (modeOption)
            {
            case 1:
            { // ECB
                CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryption;
                encryption.SetKey(key.BytePtr(), key.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 2:
            { // CBC
                CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 3:
            { // OFB
                CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption encryption;
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 4:
            { // CFB
                CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryption;
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 5:
            { // CTR
                CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption encryption;
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 6:
            { // XTS
                // XTS mode requires two independent keys. Here we simply split the key.
                CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption encryption;
                CryptoPP::SecByteBlock key1(key, key.size() / 2);
                CryptoPP::SecByteBlock key2(key.size() / 2);
                memcpy(key2, key.BytePtr() + key.size() / 2, key.size() / 2);
                encryption.SetKeyWithIV(key1.BytePtr(), key1.size(), key2.BytePtr(), key2.size());
                // XTS uses a tweak value; we use iv for demonstration purposes.
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext), CryptoPP::StreamTransformationFilter::ZEROS_PADDING));
                break;
            }
            case 7:
            { // CCM (authenticated)
                CryptoPP::CCM<CryptoPP::AES, 16>::Encryption encryption;
                // For CCM, iv is used as nonce. Here we assume an 8-byte nonce.
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), 8);
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::AuthenticatedEncryptionFilter(encryption,
                                                                                      new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 8:
            { // GCM (authenticated)
                CryptoPP::GCM<CryptoPP::AES>::Encryption encryption;
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::AuthenticatedEncryptionFilter(encryption,
                                                                                      new CryptoPP::StringSink(ciphertext)));
                break;
            }
            default:
                throw runtime_error("Invalid mode option for AES");
            }
            break;
        }
        case ALGO_DES:
        {
            switch (modeOption)
            {
            case 1:
            { // ECB
                CryptoPP::ECB_Mode<CryptoPP::DES>::Encryption encryption;
                encryption.SetKey(key.BytePtr(), key.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 2:
            { // CBC
                CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption encryption;
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 3:
            { // OFB
                CryptoPP::OFB_Mode<CryptoPP::DES>::Encryption encryption;
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 4:
            { // CFB
                CryptoPP::CFB_Mode<CryptoPP::DES>::Encryption encryption;
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            case 5:
            { // CTR
                CryptoPP::CTR_Mode<CryptoPP::DES>::Encryption encryption;
                encryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(plaintext, true,
                                          new CryptoPP::StreamTransformationFilter(encryption,
                                                                                   new CryptoPP::StringSink(ciphertext)));
                break;
            }
            default:
                throw runtime_error("Selected mode is not supported for DES");
            }
            break;
        }
        default:
            throw runtime_error("Invalid algorithm");
        }
    }
    catch (const CryptoPP::Exception &e)
    {
        throw runtime_error("Encryption error: " + string(e.what()));
    }
    return ciphertext;
}

string Decrypt(const string &ciphertext, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv, CipherAlgorithm algo, int modeOption)
{
    string recovered;
    try
    {
        switch (algo)
        {
        case ALGO_AES:
        {
            switch (modeOption)
            {
            case 1:
            { // ECB
                CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption decryption;
                decryption.SetKey(key.BytePtr(), key.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            case 2:
            { // CBC
                CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            case 3:
            { // OFB
                CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            case 4:
            { // CFB
                CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            case 5:
            { // CTR
                CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            case 6:
            { // XTS
                CryptoPP::XTS_Mode<CryptoPP::AES>::Decryption decryption;
                CryptoPP::SecByteBlock key1(key, key.size() / 2);
                CryptoPP::SecByteBlock key2(key.size() / 2);
                memcpy(key2, key.BytePtr() + key.size() / 2, key.size() / 2);
                decryption.SetKeyWithIV(key1.BytePtr(), key1.size(), key2.BytePtr(), key2.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered), CryptoPP::StreamTransformationFilter::ZEROS_PADDING));
                break;
            }
            case 7:
            { // CCM
                CryptoPP::CCM<CryptoPP::AES, 16>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), 8);
                // Use a StringSink with the AuthenticatedDecryptionFilter to get the recovered text
                CryptoPP::AuthenticatedDecryptionFilter df(decryption, new CryptoPP::StringSink(recovered));
                CryptoPP::StringSource ss(ciphertext, true, new CryptoPP::Redirector(df));
                if (!df.GetLastResult())
                    throw runtime_error("CCM decryption failed, authentication tag mismatch");
                break;
            }
            case 8:
            { // GCM
                CryptoPP::GCM<CryptoPP::AES>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::AuthenticatedDecryptionFilter df(decryption, new CryptoPP::StringSink(recovered));
                CryptoPP::StringSource ss(ciphertext, true, new CryptoPP::Redirector(df));
                if (!df.GetLastResult())
                    throw runtime_error("GCM decryption failed, authentication tag mismatch");
                break;
            }
            default:
                throw runtime_error("Invalid mode option for AES");
            }
            break;
        }
        case ALGO_DES:
        {
            switch (modeOption)
            {
            case 1:
            { // ECB
                CryptoPP::ECB_Mode<CryptoPP::DES>::Decryption decryption;
                decryption.SetKey(key.BytePtr(), key.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            case 2:
            { // CBC
                CryptoPP::CBC_Mode<CryptoPP::DES>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            case 3:
            { // OFB
                CryptoPP::OFB_Mode<CryptoPP::DES>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            case 4:
            { // CFB
                CryptoPP::CFB_Mode<CryptoPP::DES>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            case 5:
            { // CTR
                CryptoPP::CTR_Mode<CryptoPP::DES>::Decryption decryption;
                decryption.SetKeyWithIV(key.BytePtr(), key.size(), iv.BytePtr(), iv.size());
                CryptoPP::StringSource ss(ciphertext, true,
                                          new CryptoPP::StreamTransformationFilter(decryption,
                                                                                   new CryptoPP::StringSink(recovered)));
                break;
            }
            default:
                throw runtime_error("Selected mode is not supported for DES");
            }
            break;
        }
        default:
            throw runtime_error("Invalid algorithm");
        }
    }
    catch (const CryptoPP::Exception &e)
    {
        throw runtime_error("Decryption error: " + string(e.what()));
    }
    return recovered;
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    try
    {
        int algoChoice, modeChoice;
        int keyOption, textOption;

        cout << "Lab 1: Cryptopp DES/AES Encryption-Decryption" << endl;
        cout << "Select Algorithm: 1. DES  2. AES: ";
        cin >> algoChoice;
        CipherAlgorithm algo = (algoChoice == 1) ? ALGO_DES : ALGO_AES;

        cout << "\nSelect Mode:" << endl;
        if (algo == ALGO_AES)
        {
            cout << "1. ECB\n2. CBC\n3. OFB\n4. CFB\n5. CTR\n6. XTS\n7. CCM\n8. GCM\n";
        }
        else
        {
            cout << "1. ECB\n2. CBC\n3. OFB\n4. CFB\n5. CTR\n";
        }
        cout << "Enter mode option: ";
        cin >> modeChoice;

        // Key and IV generation or loading
        cout << "\nKey Generation Options:" << endl;
        cout << "1. Randomly generate key/IV\n2. Read key/IV from file" << endl;
        cout << "Enter option: ";
        cin >> keyOption;

        size_t keySize = (algo == ALGO_AES) ? 16 : 8; // AES key length is 16 bytes, DES key length is 8 bytes
        size_t ivSize = (algo == ALGO_AES) ? static_cast<size_t>(CryptoPP::AES::BLOCKSIZE) : static_cast<size_t>(CryptoPP::DES::BLOCKSIZE);
        CryptoPP::SecByteBlock key(keySize), iv(ivSize);

        if (keyOption == 1)
        {
            GenerateRandom(key, keySize);
            GenerateRandom(iv, ivSize);
        }
        else
        {
            string keyFile, ivFile;
            cout << "Enter key file name: ";
            cin >> keyFile;
            cout << "Enter IV file name: ";
            cin >> ivFile;
            string keyStr = ReadFromFile(keyFile);
            string ivStr = ReadFromFile(ivFile);
            if (keyStr.size() < keySize || ivStr.size() < ivSize)
                throw runtime_error("Key or IV file content too short");
            memcpy(key, keyStr.data(), keySize);
            memcpy(iv, ivStr.data(), ivSize);
        }

        // Plaintext input options
        cout << "\nPlaintext Input Options:" << endl;
        cout << "1. Input plaintext from screen\n2. Read plaintext from file" << endl;
        cout << "Enter option: ";
        cin >> textOption;
        string plaintext;
        cin.ignore(); // clear newline
        if (textOption == 1)
        {
            cout << "Enter plaintext (supports UTF-8, Vietnamese): ";
            getline(cin, plaintext);
        }
        else
        {
            string textFile;
            cout << "Enter plaintext file name: ";
            cin >> textFile;
            plaintext = ReadFromFile(textFile);
        }

        // Encrypt plaintext
        auto startEncrypt = std::chrono::steady_clock::now();
        string cipher = Encrypt(plaintext, key, iv, algo, modeChoice);
        auto endEncrypt = std::chrono::steady_clock::now();
        auto encryptDuration = std::chrono::duration_cast<std::chrono::microseconds>(endEncrypt - startEncrypt).count();
        cout << "\nEncryption time: " << encryptDuration << " microseconds" << endl;

        // Output encoding choice: hex or Base64
        int encodeChoice;
        cout << "\nSelect output encoding: 1. Hex  2. Base64: ";
        cin >> encodeChoice;
        string output;
        if (encodeChoice == 1)
            output = StringToHex(cipher);
        else
        {
            CryptoPP::StringSource ss(cipher, true,
                                      new CryptoPP::Base64Encoder(new CryptoPP::StringSink(output)));
        }

        // Display ciphertext and write to file
        cout << "\nEncrypted ciphertext:\n"
             << output << endl;
        string outFile;
        cout << "Enter file name to write ciphertext: ";
        cin >> outFile;
        WriteToFile(outFile, output);

        // Ask user if decryption is desired
        char decryptChoice;
        cout << "\nDo you want to decrypt? (y/n): ";
        cin >> decryptChoice;
        if (decryptChoice == 'y' || decryptChoice == 'Y')
        {
            auto startDecrypt = std::chrono::steady_clock::now();
            string decrypted = Decrypt(cipher, key, iv, algo, modeChoice);
            auto endDecrypt = std::chrono::steady_clock::now();
            auto decryptDuration = std::chrono::duration_cast<std::chrono::microseconds>(endDecrypt - startDecrypt).count();
            cout << "\nDecryption time: " << decryptDuration << " microseconds" << endl;
            cout << "\nDecrypted text:\n"
                 << decrypted << endl;
        }
    }
    catch (const exception &ex)
    {
        cerr << "Error: " << ex.what() << endl;
    }
    return 0;
}