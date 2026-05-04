/**
 * @file aes.c
 * @brief AES-128 implementation for WPA2 support
 * @note Simplified for embedded systems with limited RAM
 */
#include <string.h>
#include <stdint.h>
#include "net/aes.h"

/* AES S-Box */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t xtime(uint8_t x)
{
    return ((x << 1) ^ (((x & 0x80) != 0) ? 0x1b : 0x00));
}

static void key_expansion(const uint8_t *key, uint8_t *round_key)
{
    uint8_t i, j, tempa[4];

    for(i = 0; i < 4; i++) {
        round_key[i * 4] = key[i * 4];
        round_key[i * 4 + 1] = key[i * 4 + 1];
        round_key[i * 4 + 2] = key[i * 4 + 2];
        round_key[i * 4 + 3] = key[i * 4 + 3];
    }

    for(i = 4; i < 44; i++) {
        j = (i - 1) * 4;
        tempa[0] = round_key[j];
        tempa[1] = round_key[j + 1];
        tempa[2] = round_key[j + 2];
        tempa[3] = round_key[j + 3];

        if(i % 4 == 0) {
            tempa[0] = sbox[tempa[1]] ^ rcon[i / 4];
            tempa[1] = sbox[tempa[2]];
            tempa[2] = sbox[tempa[3]];
            tempa[3] = sbox[tempa[0]];
        }

        j = i * 4;
        round_key[j] = round_key[j - 4] ^ tempa[0];
        round_key[j + 1] = round_key[j - 3] ^ tempa[1];
        round_key[j + 2] = round_key[j - 2] ^ tempa[2];
        round_key[j + 3] = round_key[j - 1] ^ tempa[3];
    }
}

static void add_round_key(uint8_t round, uint8_t *state, const uint8_t *round_key)
{
    uint8_t i;
    for(i = 0; i < 16; i++) {
        state[i] ^= round_key[(round * 16) + i];
    }
}

static void sub_bytes(uint8_t *state)
{
    uint8_t i;
    for(i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void shift_rows(uint8_t *state)
{
    uint8_t temp;

    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = temp;
    temp = state[15];
    state[15] = state[11];
    state[11] = temp;
}

static void mix_columns(uint8_t *state)
{
    uint8_t i, t, u;
    for(i = 0; i < 4; i++) {
        t = state[i * 4];
        u = state[i * 4] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        state[i * 4] ^= xtime(state[i * 4] ^ state[i * 4 + 1]);
        state[i * 4 + 1] ^= xtime(state[i * 4 + 1] ^ state[i * 4 + 2]);
        state[i * 4 + 2] ^= xtime(state[i * 4 + 2] ^ state[i * 4 + 3]);
        state[i * 4 + 3] ^= xtime(state[i * 4 + 3] ^ t);
    }
}

static void cipher(uint8_t *input, uint8_t *output, const uint8_t *round_key)
{
    uint8_t state[16];
    uint8_t round;

    memcpy(state, input, 16);

    add_round_key(0, state, round_key);

    for(round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(round, state, round_key);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(10, state, round_key);

    memcpy(output, state, 16);
}

/**
 * @brief AES-ECB encrypt (128-bit key)
 */
void aes_encrypt(const uint8_t *input, uint8_t *output, const uint8_t *key)
{
    uint8_t round_key[176];
    key_expansion(key, round_key);
    cipher(input, output, round_key);
}

/**
 * @brief AES-ECB decrypt (128-bit key) - placeholder for full implementation
 */
void aes_decrypt(const uint8_t *input, uint8_t *output, const uint8_t *key)
{
    memcpy(output, input, 16);
}

/**
 * @brief AES-CTR mode encrypt/decrypt (same operation)
 */
void aes_ctr_encrypt(const uint8_t *input, uint8_t *output, const uint8_t *key, const uint8_t *nonce, uint32_t len)
{
    uint8_t counter[16];
    uint8_t keystream[16];
    uint32_t i, block_num;

    memcpy(counter, nonce, 16);

    for(block_num = 0; block_num < len / 16; block_num++) {
        aes_encrypt(counter, keystream, key);
        for(i = 0; i < 16; i++) {
            output[block_num * 16 + i] = input[block_num * 16 + i] ^ keystream[i];
        }

        for(i = 0; i < 16; i++) {
            counter[i]++;
            if(counter[i] != 0) break;
        }
    }

    if(len % 16) {
        aes_encrypt(counter, keystream, key);
        for(i = 0; i < (len % 16); i++) {
            output[(block_num * 16) + i] = input[(block_num * 16) + i] ^ keystream[i];
        }
    }
}

/**
 * @brief AES-CCMP MIC computation (simplified)
 */
void ccmp_mic(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, uint32_t aad_len,
             const uint8_t *data, uint32_t data_len, uint8_t *mic)
{
    uint8_t block[16];
    uint8_t mic_temp[16];
    uint32_t i;

    memset(block, 0, 16);
    block[0] = 0x59;
    memcpy(block + 1, nonce, 13);

    aes_encrypt(block, mic_temp, key);

    for(i = 0; i < 16 && i < data_len; i++) {
        mic_temp[i] ^= data[i];
    }

    aes_encrypt(mic_temp, mic, key);
}