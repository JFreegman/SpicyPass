/*  crypto.cpp
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

#include <string.h>
#include <assert.h>

#include "crypto.hpp"

#define CRYPTO_MAX_CIPHER_SIZE     (crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX)
#define CRYPTO_MAX_PLAINEXT_SIZE   (crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX + crypto_secretstream_xchacha20poly1305_ABYTES)

/*
 * Inits libsodium. Must be called before any other crypto operation.
 *
 * Returns 0 on success.
 */
int crypto_init(void)
{
    if (sodium_init() < 0) {
        return -1;
    }

    return 0;
}

/*
 * Creates a hash of `password` and puts it in `hash`.
 *
 * `hash` must have room for at least CRYPTO_HASH_SIZE bytes.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_make_pass_hash(const unsigned char *hash, const unsigned char *password, size_t length)
{
    assert(length <= crypto_pwhash_PASSWD_MAX && length >= crypto_pwhash_PASSWD_MIN);

    if (crypto_pwhash_str((char *) hash, (const char *) password, length,
                         CRYPTO_DEFAULT_OPSLIMIT, CRYPTO_DEFAULT_MEMLIMIT) != 0) {
        return -1;
    }

    return 0;
}

/*
 * Securely zeros `length` bytes from memory pointed to by `buf`.
 */
void crypto_memwipe(const unsigned char *buf, size_t length)
{
    sodium_memzero((void *) buf, length);
}

/*
 * Locks `length` bytes in memory pointed to by `buf`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_memlock(const unsigned char *buf, size_t length)
{
    if (sodium_mlock((void *) buf, length) != 0) {
        return -1;
    }

    return 0;
}

/*
 * Unlocks `length` bytes in memory pointed to by `buf`.
 *
 * This function also securely wipes the memory block.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_memunlock(const unsigned char *buf, size_t length)
{
    if (sodium_munlock((void *) buf, length) != 0) {
        sodium_memzero((void *) buf, length);   // Still attempt to securely wipe memory
        return -1;
    }

    return 0;
}

/*
 * Returns true if `password` matches `hash`.
 */
bool crypto_verify_pass_hash(const unsigned char *hash, const unsigned char *password, size_t length)
{
    return crypto_pwhash_str_verify((const char *) hash, (const char *) password, length) == 0;
}

/*
 * Generates a random salt of `length` bytes and puts it in `salt`.
 */
void crypto_gen_salt(unsigned char *salt, size_t length)
{
    randombytes_buf(salt, length);
}

/*
 * Returns a random number between 0 and `upper_limit`.
 */
uint32_t crypto_random_number(const uint32_t upper_limit)
{
    return randombytes_uniform(upper_limit);
}

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
                                size_t pwlen, const unsigned char *salt)
{
    assert(pwlen <= crypto_pwhash_PASSWD_MAX && pwlen >= crypto_pwhash_PASSWD_MIN);

    if (crypto_pwhash((unsigned char *) key, keylen, (const char *) password, pwlen, salt,
                      CRYPTO_DEFAULT_OPSLIMIT, CRYPTO_DEFAULT_MEMLIMIT, CRYPTO_DEFAULT_ALGO) != 0) {
        return -1;
    }

    return 0;
}

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
                        unsigned long long *out_len, const unsigned char *key)
{
    if (file_size > CRYPTO_MAX_PLAINEXT_SIZE) {
        return -1;
    }

    unsigned char tag;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;

    size_t buf_in_size = file_size + crypto_secretstream_xchacha20poly1305_ABYTES;
    unsigned char *buf_in = (unsigned char *) malloc(buf_in_size);

    if (buf_in == NULL) {
        return -1;
    }

    fp.read((char *) header, sizeof(header));

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0) {
        free(buf_in);
        return -2;
    }

    fp.read((char *) buf_in, buf_in_size);

    if (crypto_secretstream_xchacha20poly1305_pull(&state, output, out_len, &tag, buf_in, fp.gcount(), NULL, 0) != 0) {
        free(buf_in);
        return -2;
    }

    free(buf_in);

    if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL || !fp.eof() || *out_len > file_size) {
        return -3;
    }

    return 0;
}

/*
 * Encrypts contents of `input` and saves it to file pointed to by `fp` using `key`. Puts length of
 * ciphertext in `out_len`.
 *
 * Return 0 on success.
 * Return -1 on memory related error.
 * Return -2 on encryption error.
 */
int crypto_encrypt_file(std::ofstream &fp, const unsigned char *input, size_t in_len,
                        unsigned long long *out_len, const unsigned char *key)
{
    if (in_len > CRYPTO_MAX_CIPHER_SIZE) {
        return -1;
    }

    unsigned char *buf_out = (unsigned char *) malloc(in_len + crypto_secretstream_xchacha20poly1305_ABYTES);

    if (buf_out == NULL) {
        return -1;
    }

    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
    fp.write((char *)header, sizeof(header));

    crypto_secretstream_xchacha20poly1305_push(&state, buf_out, out_len, input, in_len, NULL, 0,
                                               crypto_secretstream_xchacha20poly1305_TAG_FINAL);

    if (*out_len != in_len + crypto_secretstream_xchacha20poly1305_ABYTES) {
        free(buf_out);
        return -2;
    }

    fp.write((char *)buf_out, *out_len);

    free(buf_out);

    return 0;
}
