/**
 * @file hash.h
 * @author Sebastien Bourdeauducq - 2006 - Initial version
 * @author RedoX <dev@redox.ws> - 2015 - GCC Port, cleanup
 * @date 2015/09/07
 * @brief MD5/SHA1 hash utils
 */
#ifndef _HASH_H_
#define _HASH_H_

void hmac_md5(const uint8_t *key, uint32_t key_len,
              const uint8_t *data, uint32_t data_len,
              uint8_t *mac);
void hmac_sha1( const uint8_t *key, uint32_t key_len,
                const uint8_t *data, uint32_t data_len,
                uint8_t *mac);
void hmac_sha256(const uint8_t *key, uint32_t key_len,
                 const uint8_t *data, uint32_t data_len,
                 uint8_t *mac);
void pbkdf2_sha256(const uint8_t *password, uint32_t password_len,
                   const uint8_t *salt, uint32_t salt_len,
                   uint32_t iterations,
                   uint8_t *output);

#endif
