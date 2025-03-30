#include "AES.h"
#include "KeyExpansion.h"

#include <stdexcept>

const uint8_t AES::sbox[256] = {
    // S-box values
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

const uint8_t AES::inv_sbox[256] = {
    // Inverse S-box values
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

static const std::vector<std::vector<uint8_t>> rcon = {
    {0x01, 0x00, 0x00, 0x00},
    {0x02, 0x00, 0x00, 0x00},
    {0x04, 0x00, 0x00, 0x00},
    {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00},
    {0x20, 0x00, 0x00, 0x00},
    {0x40, 0x00, 0x00, 0x00},
    {0x80, 0x00, 0x00, 0x00},
    {0x1B, 0x00, 0x00, 0x00},
    {0x36, 0x00, 0x00, 0x00}};

std::vector<std::vector<uint8_t>> AES::key_expansion(const std::vector<uint8_t> &key, int length)
{
    if (length == 128)
        return key_expansion_128();
    else if (length == 192)
        return key_expansion_192();
    else if (length == 256)
        return key_expansion_256();
    else
        throw std::runtime_error("Invalid key length. Supported lengths are 128, 192, and 256 bits.");
}

AES::AES(const std::vector<uint8_t> &key, int key_length) : key(key), key_length(key_length)
{
}

std::vector<uint8_t> AES::sub_word(const std::vector<uint8_t> &word)
{
    std::vector<uint8_t> result(4);
    for (int i = 0; i < 4; i++)
    {
        result[i] = sbox[word[i]];
    }
    return result;
}

std::vector<uint8_t> AES::rot_word(const std::vector<uint8_t> &word)
{
    std::vector<uint8_t> result = {word[1], word[2], word[3], word[0]};
    return result;
}

std::vector<std::vector<uint8_t>> AES::key_expansion_128()
{
    int key_size = 16; // Note: length of the key
    int key_words = 4; // Note: key_size / 4

    // The first w[0], w[1], ... w[3] come from the original key
    std::vector<std::vector<uint8_t>> round_keys;
    for (int i = 0; i < key_size; i += 4)
    {
        round_keys.push_back(std::vector<uint8_t>(key.begin() + i, key.begin() + i + 4));
    }

    // Extend the key up to 44 words (iteration)
    for (int i = key_words; i < 44; ++i)
    { // 44 words for AES-128
        std::vector<uint8_t> temp = round_keys[i - 1];
        if (i % key_words == 0)
        {
            temp = this->sub_word(rot_word(temp));
            for (int j = 0; j < 4; ++j)
            {
                temp[j] ^= rcon[(i - key_words) / key_words][j]; // Note: ^= ⊕
            }
        }
        std::vector<uint8_t> new_word(4);
        for (int j = 0; j < 4; ++j)
        {
            new_word[j] = round_keys[i - key_words][j] ^ temp[j];
        }
        round_keys.push_back(new_word);
    }
    return round_keys;
}

std::vector<std::vector<uint8_t>> AES::key_expansion_192()
{
    std::vector<std::vector<uint8_t>> round_keys;
    for (int i = 0; i < 24; i += 4)
    {
        round_keys.push_back(std::vector<uint8_t>(key.begin() + i, key.begin() + i + 4));
    }

    // 52 words for AES-192
    for (int i = 6; i < 52; i++)
    {
        std::vector<uint8_t> temp = round_keys[i - 1];
        if (i % 6 == 0)
        {
            temp = this->sub_word(rot_word(temp));
            for (int j = 0; j < 4; ++j)
            {
                temp[j] ^= rcon[(i - 6) / 6][j]; // Note: ^= ⊕
            }
        }
        std::vector<uint8_t> new_word(4);
        for (int j = 0; j < 4; ++j)
        {
            new_word[j] = round_keys[i - 6][j] ^ temp[j];
        }
        round_keys.push_back(new_word);
    }
    return round_keys;
}

std::vector<std::vector<uint8_t>> AES::key_expansion_256()
{
    // Initialize the round keys with the original key
    std::vector<std::vector<uint8_t>> round_keys;
    for (int i = 0; i < 32; i += 4)
    {
        round_keys.push_back(std::vector<uint8_t>(key.begin() + i, key.begin() + i + 4));
    }

    // 60 words for AES-256
    for (int i = 8; i < 60; i++)
    {
        std::vector<uint8_t> temp = round_keys[i - 1];
        if (i % 8 == 0)
        {
            temp = this->sub_word(rot_word(temp));
            for (int j = 0; j < 4; ++j)
            {
                temp[j] ^= rcon[(i - 8) / 8][j]; // Note: ^= ⊕
            }
        }
        else if (i % 8 == 4)
        {
            temp = this->sub_word(temp);
        }
        std::vector<uint8_t> new_word(4);
        for (int j = 0; j < 4; ++j)
        {
            new_word[j] = round_keys[i - 8][j] ^ temp[j];
        }
        round_keys.push_back(new_word);
    }
    return round_keys;
}

std::vector<std::vector<uint8_t>> AES::sub_bytes(std::vector<std::vector<uint8_t>> &state)
{
    /*
    Substitute each byte in the state with its corresponding byte in the S-box.
    */
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            // Extraqt the row and column from the state matrix
            uint8_t row = state[i][j] / 0x10;
            uint8_t col = state[i][j] % 0x10;
            // Substitute the value using the S-box
            state[i][j] = sbox[16 * row + col];
        }
    }
    return state;
}

std::vector<std::vector<uint8_t>> AES::shift_rows(std::vector<std::vector<uint8_t>> &state)
{
    /*
    Cyclically shift the rows of the state.
    */
    // Second row: shift left by one byte
    std::vector<uint8_t> temp = {state[1][1], state[1][2], state[1][3], state[1][0]};
    state[1] = temp;

    // Third row: shift left by two bytes
    temp = {state[2][2], state[2][3], state[2][0], state[2][1]};
    state[2] = temp;

    // Fourth row: shift left by three bytes
    temp = {state[3][3], state[3][0], state[3][1], state[3][2]};
    state[3] = temp;

    return state;
}

uint8_t AES::gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            p ^= a;
        }
        uint8_t hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set)
        {
            a &= 0x1b;
        }
        b >>= 1;
    }
    return p % 256;
}

std::vector<std::vector<uint8_t>> AES::mix_columns(std::vector<std::vector<uint8_t>> &state)
{
    /*
    Mix the columns of the state.
    */
    for (int i = 0; i < 4; i++)
    {
        std::vector<uint8_t> col(4);
        for (int j = 0; j < 4; j++)
        {
            col[j] = state[j][i];
        }

        state[0][i] = gmul(0x02, col[0]) ^ gmul(0x03, col[1]) ^ col[2] ^ col[3];
        state[1][i] = col[0] ^ gmul(0x02, col[1]) ^ gmul(0x03, col[2]) ^ col[3];
        state[2][i] = col[0] ^ col[1] ^ gmul(0x02, col[2]) ^ gmul(0x03, col[3]);
        state[3][i] = gmul(0x03, col[0]) ^ col[1] ^ col[2] ^ gmul(0x02, col[3]);
    }
    return state;
}

// Add round key (to hide input message)
std::vector<std::vector<uint8_t>> AES::add_round_key(std::vector<std::vector<uint8_t>> &state, int roundNumber)
{
    /*
    Add (XOR) the round key to the state.
    */
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            state[j][i] ^= round_keys[roundNumber * 4 * i][j];
        }
    }
    return state;
}

// Decryption functions
std::vector<std::vector<uint8_t>> AES::inv_sub_bytes(std::vector<std::vector<uint8_t>> &state)
{
    // Inverse substitute bytes using the inverse S-box.
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            uint8_t row = state[i][j] / 0x10;
            uint8_t col = state[i][j] % 0x10;
            state[i][j] = inv_sbox[16 * row + col];
        }
    }
    return state;
}

std::vector<std::vector<uint8_t>> AES::inv_shift_rows(std::vector<std::vector<uint8_t>> &state)
{
    // Inverse shift rows to the right.
    std::vector<uint8_t> temp = {state[1][3], state[1][0], state[1][1], state[1][2]};
    state[1] = temp;

    temp = {state[2][2], state[2][3], state[2][0], state[2][1]};
    state[2] = temp;

    temp = {state[3][1], state[3][2], state[3][3], state[3][0]};
    state[3] = temp;

    return state;
}

// Invert Mix columns (subtitution for decrypt)
std::vector<std::vector<uint8_t>> AES::inv_mix_columns(std::vector<std::vector<uint8_t>> &state)
{
    // Inverse mix columns of the state.
    for (int i = 0; i < 4; i++)
    {
        std::vector<uint8_t> col(4);
        for (int j = 0; j < 4; j++)
        {
            col[j] = state[j][i];
        }
        state[0][i] = gmul(0x0e, col[0]) ^ gmul(0x0b, col[1]) ^ gmul(0x0d, col[2]) ^ gmul(0x09, col[3]);
        state[1][i] = gmul(0x09, col[0]) ^ gmul(0x0e, col[1]) ^ gmul(0x0b, col[2]) ^ gmul(0x0d, col[3]);
        state[2][i] = gmul(0x0d, col[0]) ^ gmul(0x09, col[1]) ^ gmul(0x0e, col[2]) ^ gmul(0x0b, col[3]);
        state[3][i] = gmul(0x0b, col[0]) ^ gmul(0x0d, col[1]) ^ gmul(0x09, col[2]) ^ gmul(0x0e, col[3]);
    }
    return state;
}

std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t> &plaintext)
{
    // Generate round_keys if not already avilable
    if (round_keys.empty())
    {
        round_keys = key_expansion(key, key_length);
    }

    // Convert plaintext into state matrix
    std::vector<std::vector<uint8_t>> state(4, std::vector<uint8_t>(4));
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            state[j][i] = plaintext[i * 4 + j];
        }
    }
    // Numbers of rounds depend on the key length: 10 for 128, 12 for 192, and 14 for 256
    int num_rounds = (this->key.size() == 16) ? 10 : (this->key.size() == 24) ? 12
                                                                              : 14;
    // Initial round
    state = add_round_key(state, 0);

    // Main rounds
    for (int round = 1; round < num_rounds; round++)
    {
        state = sub_bytes(state);
        state = shift_rows(state);
        state = mix_columns(state);
        state = add_round_key(state, round);
    }

    // Final round
    state = sub_bytes(state);
    state = shift_rows(state);
    state = add_round_key(state, num_rounds);
    // Convert state matrix back to bytes
    std::vector<uint8_t> result;
    for (const auto &row : state)
    {
        result.insert(result.end(), row.begin(), row.end());
    }
    return result;
}

std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t> &ciphertext)
{
    // Generate round_keys if not already available
    if (round_keys.empty())
    {
        round_keys = key_expansion(key, key_length);
    }

    // Convert ciphertext into state matrix
    std::vector<std::vector<uint8_t>> state(4, std::vector<uint8_t>(4));
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            state[j][i] = ciphertext[i * 4 + j];
        }
    }

    // Numbers of rounds depend on the key length: 10 for 128, 12 for 192, and 14 for 256
    int num_rounds = (this->key.size() == 16) ? 10 : (this->key.size() == 24) ? 12
                                                                              : 14;
    // Initial round
    state = add_round_key(state, num_rounds);

    // Main rounds
    for (int round = num_rounds - 1; round > 0; round--)
    {
        state = inv_shift_rows(state);
        state = inv_sub_bytes(state);
        state = add_round_key(state, round);
        state = inv_mix_columns(state);
    }

    // Final round
    state = inv_shift_rows(state);
    state = inv_sub_bytes(state);
    state = add_round_key(state, 0);

    // Convert state matrix back to bytes
    std::vector<uint8_t> result;
    for (const auto &row : state)
    {
        result.insert(result.end(), row.begin(), row.end());
    }
    return result;
}