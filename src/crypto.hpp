/*  crypto.hpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#if defined(_WIN32)
#define SODIUM_STATIC
#pragma comment (lib, "libsodium.lib")
#endif

#include <sodium.h>

#include <string>
#include <stdint.h>

#include <iostream>
#include <fstream>

#define CRYPTO_KEY_SIZE     (crypto_secretstream_xchacha20poly1305_KEYBYTES)
#define CRYPTO_SALT_SIZE    (crypto_pwhash_SALTBYTES)
#define CRYPTO_HASH_SIZE    (crypto_pwhash_STRBYTES)

#define CRYPTO_DEFAULT_OPSLIMIT (crypto_pwhash_OPSLIMIT_SENSITIVE)
#define CRYPTO_DEFAULT_MEMLIMIT (crypto_pwhash_MEMLIMIT_MODERATE)

typedef struct Hash_Parameters {
    size_t memory_limit;
    unsigned long long ops_limit;
    int algorithm;
} Hash_Parameters;

/*
 * Inits libsodium. Must be called before any other crypto operation.
 *
 * Returns 0 on success.
 */
int crypto_init(void);

/*
 * Returns a random number between 0 and `upper_limit` (excluded).
 */
uint32_t crypto_random_number(const uint32_t upper_limit);

/*
 * Securely zeros `length` bytes from memory pointed to by `buf`.
 *
 * If `length` is zero this function has no effect.
 */
void crypto_memwipe(unsigned char *buf, size_t length);

/*
 * Locks `length` bytes in memory pointed to by `buf`. If `length` is 0
 * this function has no effect.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_memlock(const unsigned char *buf, size_t length);

/*
 * Unlocks `length` bytes in memory pointed to by `buf`.
 *
 * This function also securely wipes the memory block.
 *
 * If `length` is zero this function has no effect.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_memunlock(const unsigned char *buf, size_t length);

/*
 * Creates a hash of `password` and puts it in `hash`.
 *
 * `hash` must have room for at least CRYPTO_HASH_SIZE bytes.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_make_pass_hash(unsigned char *hash, const unsigned char *password, size_t length);

/*
 * Returns true if password matches hash.
 */
bool crypto_verify_pass_hash(const unsigned char *hash, const unsigned char *password, size_t length);

/*
 * Derives an encryption key from `password` and `salt` combo, and puts it in `key`.
 *
 * `salt` must be a random number and should be at least CRYPTO_SALT_SIZE bytes. See: crypto_gen_salt().
 * `keylen` must be at least 32 bytes.
 * `params` must contain the same parameters that the key was originally derived with.
 *
 * This key is responsible for all encryption and decryption operations, and therefore must be
 * kept secret.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_derive_key_from_pass(unsigned char *key, size_t keylen, const unsigned char *password,
                                size_t pwlen, const unsigned char *salt, Hash_Parameters *params);

/*
 * Generates a random salt of CRYPTO_SALT_SIZE bytes in length. `salt` must have room
 * for at least that many bytes.
 */
void crypto_gen_salt(unsigned char *salt);

/*
 * Decrypts file pointed to by `fp` using `key`. Puts result in `plaintext` and the
 * size of the plaintext in `plain_len`.
 *
 * Return 0 on success.
 * Return -1 on memory related error.
 * Return -2 on decryption error.
 * Return -3 on file corruption related error.
 */
int crypto_decrypt_file(std::ifstream &fp, size_t file_size, unsigned char *plaintext,
                        unsigned long long *plain_len, const unsigned char *key);

/*
 * Encrypts contents of `plaintext` using `key` and saves it to file pointed to by `fp`.
 * Puts length of ciphertext in `cipher_len`.
 *
 * Return 0 on success.
 * Return -1 on memory related error.
 * Return -2 on encryption error.
 * Return -3 on write error.
 */
int crypto_encrypt_file(std::ofstream &fp, const unsigned char *plaintext, size_t plain_len,
                        unsigned long long *cipher_len, const unsigned char *key);

#endif //CRYPTO_H
