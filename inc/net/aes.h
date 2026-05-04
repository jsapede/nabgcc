/**
 * @file aes.h
 * @brief AES cryptographic functions header
 */
#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#define AES_KEYLEN_128    16
#define AES_BLOCK_SIZE   16
#define CCMP_MIC_LEN     8
#define CCMP_NONCE_LEN   13

void aes_encrypt(const uint8_t *input, uint8_t *output, const uint8_t *key);
void aes_decrypt(const uint8_t *input, uint8_t *output, const uint8_t *key);
void aes_ctr_encrypt(const uint8_t *input, uint8_t *output, const uint8_t *key, const uint8_t *nonce, uint32_t len);
void ccmp_mic(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, uint32_t aad_len, const uint8_t *data, uint32_t data_len, uint8_t *mic);

#endif