/*  based.hpp
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

#ifndef BASED
#define BASED

#include <iostream>
#include <string>
#include <fstream>
#include <map>

#include <string.h>

#include "load.hpp"
#include "util.hpp"
#include "crypto.hpp"

using namespace std;


#define DELIMITER ":"
#define MAX_ENTRY_KEY_SIZE        (64)
#define MAX_STORE_PASSWORD_SIZE   (64)
#define MIN_STORE_PASSWORD_SIZE   (8)


/*
 * We used this struct to store passwords in the store map so that
 * they can be securely wiped from memory when no longer in use.
 */
struct Password {
    char password[MAX_STORE_PASSWORD_SIZE + 1];
};


class Pass_Store {
    map<string, struct Password *> store;

    unsigned char encryption_key[CRYPTO_KEY_SIZE];
    unsigned char key_salt[CRYPTO_SALT_SIZE];
    unsigned char password_hash[CRYPTO_HASH_SIZE];

public:
    /*
     * Inserts `key` into pass store with `value`. If key already exists it will
     * be overwritten.
     *
     * Return 0 on sucess.
     * Return -1 on failure.
     */
    int insert(string key, string value) {
        struct Password *pass = (struct Password *) calloc(1, sizeof(struct Password));

        if (pass == NULL) {
            return -1;
        }

        size_t length = value.size();

        if (length >= sizeof(pass->password)) {
            free(pass);
            return -1;
        }

        memcpy(pass->password, value.c_str(), length);
        pass->password[length] = 0;

        if (crypto_memlock((unsigned char *) pass->password, sizeof(pass->password)) != 0) {
            free(pass);
            return -1;
        }

        // manually delete key if it already exists so that memory is properly wiped and freed
        remove(key);

        try {
            store.insert({key, pass});
        } catch (const exception &) {
            free(pass);
            return -1;
        }

        return 0;
    }

    /*
     * Removes `key` from pass store.
     *
     * Return 0 on success.
     * Return -1 if key does not exist.
     */
    int remove(string key) {
        if (!key_exists(key)) {
            return -1;
        }

        crypto_memunlock((unsigned char *) store.at(key)->password, sizeof(store.at(key)->password));
        free(store.at(key));
        store.erase(key);

        return 0;
    }

    /*
     * Return true if `key` exists in pass store.
     */
    bool key_exists(string key) {
        return store.find(key) != store.end();
    }

    /*
     * Prints all key:value pairs in pass store.
     */
    bool print_matches(string key) {
        bool match = false;

        for (auto &item: store) {
            if (key.compare(0, key.length(), item.first, 0, key.length()) == 0) {
                cout << item.first << ": " << item.second->password << endl;
                match = true;
            }
        }

        return match;
    }

    /*
     * Puts key salt in `buf`.
     *
     * buf must have room for at least CRYPTO_SALT_SIZE bytes.
     */
    void get_key_salt(unsigned char *buf) {
        memcpy(buf, key_salt, CRYPTO_SALT_SIZE);
    }

    /*
     * Puts password hash in `buf`.
     *
     * buf must have room for at least CRYPTO_HASH_SIZE bytes.
     */
    void get_password_hash(unsigned char *buf) {
        memcpy(buf, password_hash, CRYPTO_HASH_SIZE);
    }

    int init_crypto(const unsigned char *key, const unsigned char *salt, const unsigned char *hash) {
        memcpy(encryption_key, key, CRYPTO_KEY_SIZE);
        memcpy(key_salt, salt, CRYPTO_SALT_SIZE);
        memcpy(password_hash, hash, CRYPTO_HASH_SIZE);

        if (crypto_memlock(encryption_key, CRYPTO_KEY_SIZE) != 0) {
            return -1;
        }

        return 0;
    }

    /*
     * Decrypts file contents of size `length` pointed to by `fp` and loads to pass store.
     *
     * Return -1 on out of memory error.
     * Return -2 on decryption error.
     */
    int load(ifstream &fp, size_t length) {
        unsigned char *plaintext = (unsigned char *) malloc(length + 1);
        unsigned long long plain_length = 0;

        int ret = crypto_decrypt_file(fp, length, plaintext, &plain_length, encryption_key);

        if (ret != 0) {
            free(plaintext);

            switch (ret) {
                case -1: {
                    cout << "Decryption failed: Out of memory" << endl;
                    return -2;
                }
                case -2: {
                    cout << "Decryption failed: Corrupt file or bad key" << endl;
                    return -2;
                }
                case -3: {
                    cout << "Decryption failed: File corrupt" << endl;
                    return -2;
                }
                default: {
                    return -2;
                }
            }
        }

        plaintext[plain_length] = 0;

        char *tok = strtok((char *) plaintext, "\n");

        while (tok) {
            string entry = tok;
            auto d = entry.find(DELIMITER);

            if (d != string::npos) {
                string key = entry.substr(0, d);
                string pass = entry.substr(d + 1, entry.length());
                insert(key, pass);
            }

            tok = strtok(NULL, "\n");
        }

        crypto_memwipe(plaintext, plain_length);
        free(plaintext);

        return 0;
    }

    /*
     * Encrypts pass store data and saves result to file pointed to by `fp`.
     * fp should be offset to after the plaintext header.
     *
     * Return 0 on success.
     * Return -1 on memory related error.
     * Return -2 if encryption fails.
     */
    int save(ofstream &fp) {
        size_t file_size = 0;

        for (auto &item: store) {
            string val(item.second->password);
            string entry = item.first + DELIMITER + val + '\n';
            file_size += entry.length();
        }

        if (file_size == 0) {
            return 0;
        }

        unsigned char *buf_in = (unsigned char *) malloc(file_size);

        if (buf_in == NULL) {
            return -1;
        }

        size_t pos = 0;

        for (auto &item: store) {
            string val(item.second->password);
            string entry = item.first + DELIMITER + val + '\n';
            memcpy(buf_in + pos, entry.c_str(), entry.length());
            pos += entry.length();
        }

        unsigned long long out_len = 0;
        int ret = crypto_encrypt_file(fp, buf_in, file_size, &out_len, encryption_key);

        if (ret < 0) {
            crypto_memwipe(buf_in, file_size);
            free(buf_in);
            return -2;
        }

        crypto_memwipe(buf_in, file_size);
        free(buf_in);

        return 0;
    }

    ~Pass_Store(void) {
        crypto_memunlock(encryption_key, CRYPTO_KEY_SIZE);

        for (auto &item: store) {
            remove(item.first);
        }
    }
};

#endif // BASED
