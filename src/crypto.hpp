/*  crypto.hpp
 *
 *
 *  Copyright (C) 2020 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of BasedPass.
 *
 *  BasedPass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  BasedPass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with BasedPass.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef CRYPTO
#define CRYPTO


#include <string>

#include <sodium.h>
#include <stdint.h>

#include <iostream>
#include <fstream>

#define CRYPTO_KEY_SIZE     (crypto_secretstream_xchacha20poly1305_KEYBYTES)
#define CRYPTO_SALT_SIZE    (crypto_pwhash_SALTBYTES)
#define CRYPTO_HASH_SIZE    (crypto_pwhash_STRBYTES)

#define CRYPTO_DEFAULT_OPSLIMIT (crypto_pwhash_OPSLIMIT_SENSITIVE)
#define CRYPTO_DEFAULT_MEMLIMIT (crypto_pwhash_MEMLIMIT_SENSITIVE)
#define CRYPTO_DEFAULT_ALGO     (crypto_pwhash_ALG_ARGON2ID13)

/*
 * Inits libsodium. Must be called before any other crypto operation.
 *
 * Returns 0 on success.
 */
int crypto_init(void);

/*
 * Returns a random number between 0 and `upper_limit`.
 */
uint32_t crypto_random_number(const uint32_t upper_limit);

/*
 * Securely zeros `length` bytes from memory pointed to by `buf`.
 */
void crypto_memwipe(const unsigned char *buf, size_t length);

/*
 * Locks `length` bytes in memory pointed to by `buf`.
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
int crypto_make_pass_hash(const unsigned char *hash, const unsigned char *password, size_t length);

/*
 * Returns true if password matches hash.
 */
bool crypto_verify_pass_hash(const unsigned char *hash, const unsigned char *password, size_t length);

/*
 * Derives an encryption key from `password` and `salt` combo, and puts it in `key`.
 *
 * `salt` must be a random number and should be at least CRYPTO_SALT_SIZE bytes. See: crypto_gen_salt().
 *
 * `key` must have room for at least CRYPTO_KEY_SIZE bytes.
 *
 * This key is responsible for all encryption and decryption operations, and therefore must be
 * kept secret.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_derive_key_from_pass(const unsigned char *key, size_t keylen, const unsigned char *password,
                                size_t pwlen, const unsigned char *salt);

/*
 * Generates a random salt of `length` bytes and puts it in `salt`.
 */
void crypto_gen_salt(unsigned char *salt, size_t length);

/*
 * Decrypts file pointed to by `fp` using `key`. Puts resulting plaintext in `output` and the
 * size of the plaintext in `out_len`.
 *
 * Return 0 on success.
 * Return -1 on memory related error.
 * Return -2 on decryption error.
 * Return -3 on file corruption related error.
 */
int crypto_decrypt_file(std::ifstream &fp, size_t file_size, unsigned char *output,
                        unsigned long long *out_len, const unsigned char *key);

/*
 * Encrypts contents of `input` and saves it to file pointed to by `fp` using `key`. Puts length of
 * ciphertext in `out_len`.
 *
 * Return 0 on success.
 * Return -1 on memory related error.
 * Return -2 on encryption error.
 */
int crypto_encrypt_file(std::ofstream &fp, const unsigned char *input, size_t in_len,
                        unsigned long long *out_len, const unsigned char *key);

#endif //CRYPTO
