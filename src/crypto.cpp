/*  crypto.cpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
 */

#include <string.h>
#include <assert.h>

#include "crypto.hpp"
#include "load.hpp"

#define CRYPTO_MAX_CIPHER_SIZE      (crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX)
#define CRYPTO_MAX_PLAINTEXT_SIZE   (crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX +\
                                     crypto_secretstream_xchacha20poly1305_ABYTES)

int crypto_init(void)
{
    if (sodium_init() < 0) {
        return -1;
    }

    return 0;
}

int crypto_make_pass_hash(unsigned char *hash, const unsigned char *password, size_t length)
{
    assert(length <= crypto_pwhash_PASSWD_MAX);

    if (crypto_pwhash_str((char *) hash, (const char *) password, length,
                          CRYPTO_DEFAULT_OPSLIMIT, CRYPTO_DEFAULT_MEMLIMIT) != 0) {
        return -1;
    }

    return 0;
}

void crypto_memwipe(unsigned char *buf, size_t length)
{
    sodium_memzero((void *) buf, length);
}

int crypto_memlock(unsigned char *buf, size_t length)
{
    if (sodium_mlock((void *) buf, length) != 0) {
        return -1;
    }

    return 0;
}

int crypto_memunlock(unsigned char *buf, size_t length)
{
    if (sodium_munlock((void *) buf, length) != 0) {  // this will wipe the memory even if it fails
        return -1;
    }

    return 0;
}

bool crypto_verify_pass_hash(const unsigned char *hash, const unsigned char *password, size_t length)
{
    return crypto_pwhash_str_verify((const char *) hash, (const char *) password, length) == 0;
}

void crypto_gen_salt(unsigned char *salt)
{
    randombytes_buf(salt, CRYPTO_SALT_SIZE);
}

uint32_t crypto_random_number(const uint32_t upper_limit)
{
    return randombytes_uniform(upper_limit);
}

int crypto_derive_key_from_pass(unsigned char *key, size_t keylen, const unsigned char *password,
                                size_t pwlen, const unsigned char *salt, Hash_Parameters *params)
{
    assert(pwlen <= crypto_pwhash_PASSWD_MAX);
    assert(keylen >= 32);
    assert(params->ops_limit >= crypto_pwhash_OPSLIMIT_MIN && params->ops_limit <= crypto_pwhash_OPSLIMIT_MAX);
    assert(params->memory_limit >= crypto_pwhash_MEMLIMIT_MIN && params->memory_limit <= crypto_pwhash_MEMLIMIT_MAX);

    if (crypto_pwhash(key, keylen, (const char *) password, pwlen, salt,
                      params->ops_limit, params->memory_limit, params->algorithm) != 0) {
        return -1;
    }

    return 0;
}

int crypto_decrypt_file(std::ifstream &fp, size_t file_size, unsigned char *plaintext,
                        unsigned long long *plain_len, const unsigned char *key)
{
    if (file_size > CRYPTO_MAX_PLAINTEXT_SIZE) {
        return -1;
    }

    unsigned char tag;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;

    if (file_size <= sizeof(header)) {
        return -3;
    }

    const size_t cipher_len = file_size - sizeof(header);

    unsigned char *buf_cipher = (unsigned char *) malloc(cipher_len);

    if (buf_cipher == NULL) {
        return -1;
    }

    fp.read((char *) header, sizeof(header));

    if (!fp) {
        free(buf_cipher);
        return -3;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0) {
        free(buf_cipher);
        return -2;
    }

    fp.read((char *) buf_cipher, cipher_len);

    if (!fp) {
        free(buf_cipher);
        return -3;
    }

    if (crypto_secretstream_xchacha20poly1305_pull(&state, plaintext, plain_len, &tag,
            buf_cipher, fp.gcount(), NULL, 0) != 0) {
        free(buf_cipher);
        return -2;
    }

    free(buf_cipher);

    if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        return -3;
    }

    if (*plain_len != (cipher_len - crypto_secretstream_xchacha20poly1305_ABYTES)) {
        return -3;
    }

    return 0;
}

int crypto_encrypt_file(std::ofstream &fp, const unsigned char *plaintext, size_t plain_len,
                        unsigned long long *cipher_len, const unsigned char *key)
{
    if (plain_len > CRYPTO_MAX_CIPHER_SIZE) {
        return -1;
    }

    unsigned char *buf_out = (unsigned char *) malloc(plain_len + crypto_secretstream_xchacha20poly1305_ABYTES);

    if (buf_out == NULL) {
        return -1;
    }

    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
    fp.write((char *)header, sizeof(header));

    crypto_secretstream_xchacha20poly1305_push(&state, buf_out, cipher_len, plaintext, plain_len, NULL, 0,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL);

    if (*cipher_len != plain_len + crypto_secretstream_xchacha20poly1305_ABYTES) {
        free(buf_out);
        return -2;
    }

    fp.write((char *)buf_out, *cipher_len);
    free(buf_out);

    if ((size_t) fp.tellp() != (PASS_STORE_HEADER_SIZE + *cipher_len + sizeof(header))) {
        return -3;
    }

    return 0;
}
