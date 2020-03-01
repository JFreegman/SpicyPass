/*  spicy.hpp
 *
 *
 *  Copyright (C) 2020 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass.
 *
 *  SpicyPass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SpicyPass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SpicyPass.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef SPICY
#define SPICY

#include <iostream>
#include <string>
#include <fstream>
#include <map>
#include <mutex>

#include <assert.h>
#include <string.h>

#include "load.hpp"
#include "util.hpp"
#include "crypto.hpp"

using namespace std;


#define DELIMITER ":"

#define MAX_ENTRY_KEY_SIZE        (64)
#define MAX_STORE_PASSWORD_SIZE   (64)
#define MIN_STORE_PASSWORD_SIZE   (10)

/* Seconds to wait since last activity before we prompt the user to enter their password again */
#define INACTIVE_LOCK_TIMEOUT (60U * 5U)

/* Return code indicating that `idle_lock` is set to true */
#define PASS_STORE_LOCKED (127)


/*
 * We used this struct to store passwords in the store map so that
 * they can be securely wiped from memory when no longer in use.
 */
struct Password {
    char password[MAX_STORE_PASSWORD_SIZE + 1];
};


class Pass_Store {
private:
    map<string, struct Password *> store;

    unsigned char encryption_key[CRYPTO_KEY_SIZE];
    unsigned char key_salt[CRYPTO_SALT_SIZE];
    unsigned char password_hash[CRYPTO_HASH_SIZE];

    mutex store_m;
    bool idle_lock = false;
    time_t last_active = get_time();


    /*
     * Returns a string containing a key value entry in file format.
     */
    string format_entry(string key, const char *value) {
        return key + DELIMITER + value + '\n';
    }

    /*
     * Returns the size of the store map in file format.
     */
    size_t size(void) {
        size_t size = 0;

        s_lock();

        for (auto &item: store) {
            string entry = format_entry(item.first, item.second->password);
            size += entry.length();
        }

        s_unlock();

        return size;
    }

    /*
     * Copies contents of store map into `buf` in file format.
     *
     * The `size()` method should be used to determine how large the buffer
     * needs to be.
     *
     * Returns the number of bytes copied to the buffer.
     */
    size_t copy(char *buf) {
        size_t pos = 0;

        s_lock();

        for (auto &item: store) {
            string entry = format_entry(item.first, item.second->password);
            memcpy(buf + pos, entry.c_str(), entry.length());
            pos += entry.length();
        }

        s_unlock();

        return pos;
    }

    /*
     * Loads the contents of `buf` into the pass store map.
     *
     * Buffer must be file formatted and null terminated.
     *
     * Returns the number of entries loaded to the store map.
     */
    size_t load_buffer(char *buf) {
        size_t count = 0;
        char *s = NULL;
        char *t = strtok_r((char *) buf, "\n", &s);

        while (t) {
            string entry = t;
            auto d = entry.find(DELIMITER);

            if (d != string::npos) {
                string key = entry.substr(0, d);
                string pass = entry.substr(d + 1, entry.length());

                if (insert(key, pass) != 0) {
                    cout << "Warning: Failed to load entry with key `" << key << "`" << endl;
                    continue;
                }

                ++count;
            }

            t = strtok_r(NULL, "\n", &s);
        }

        return count;
    }

    /*
     * Lock and unlock the pass store mutex.
     */
    void s_lock(void)   { store_m.lock();   }
    void s_unlock(void) { store_m.unlock(); }

public:
    /*
     * Return true if `idle_lock` is enabled. If lock is not enabled,
     * the `last_active` timer is reset.
     *
     * This should be used to block all user-prompted operations when the lock
     * in enabled.
     */
    bool check_lock(void) {
        s_lock();

        if (idle_lock) {
            s_unlock();
            return true;
        }

        last_active = get_time();
        s_unlock();

        return false;
    }

    /*
     * Sets `idle_lock` to false and resets the last active timer. This should only
     * be called immediately after the user has entered a valid master password.
     */
    void disable_lock(void) {
        s_lock();

        idle_lock = false;
        last_active = get_time();

        s_unlock();
    }

    /*
     * Polls the `last_active` timer. Upon timeout `idle_lock` is enabled and
     * all pass store functionality is disabled until `disable_lock()` is called.
     */
    void poll_idle(void) {
        s_lock();

        if (idle_lock) {
            s_unlock();
            return;
        }

        if (!timed_out(last_active, INACTIVE_LOCK_TIMEOUT)) {
            s_unlock();
            return;
        }

        idle_lock = true;
        s_unlock();

        clear();
    }

    /*
     * Inserts `key` into pass store with `value`. If key already exists it will
     * be overwritten.
     *
     * Return 0 on sucess.
     * Return -1 on failure.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int insert(string key, string value) {
        if (check_lock()) {
            return PASS_STORE_LOCKED;
        }

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

        s_lock();

        try {
            store.insert({key, pass});
        } catch (const exception &) {
            free(pass);
            s_unlock();
            return -1;
        }

        s_unlock();

        return 0;
    }

    /*
     * Removes `key` from pass store.
     *
     * Return 0 on success.
     * Return -1 if key does not exist.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int remove(string key) {
        if (check_lock()) {
            return PASS_STORE_LOCKED;
        }

        if (!key_exists(key)) {
            return -1;
        }

        s_lock();

        crypto_memunlock((unsigned char *) store.at(key)->password, sizeof(store.at(key)->password));
        free(store.at(key));
        store.erase(key);

        s_unlock();

        return 0;
    }

    /*
     * Return 1 if `key` exists in pass store.
     * Return 0 if key does not exist.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int key_exists(string key) {
        if (check_lock()) {
            return PASS_STORE_LOCKED;
        }

        s_lock();
        bool exists = store.find(key) != store.end();
        s_unlock();

        return exists ? 1 : 0;
    }

    /*
     * Prints all entries in pass store.
     *
     * Set `show_password` to true to reveal passwords.
     *
     * Return number of matches found.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int print_matches(string key, bool show_password) {
        if (check_lock()) {
            return PASS_STORE_LOCKED;
        }

        s_lock();

        int matches = 0;

        for (auto &item: store) {
            if (key.compare(0, key.length(), item.first, 0, key.length()) == 0) {
                string s = show_password ? item.first + ": " + item.second->password : item.first;
                cout << s << endl;
                ++matches;
            }
        }

        s_unlock();

        return matches;
    }

    /*
     * Puts key salt in `buf`.
     *
     * buf must have room for at least CRYPTO_SALT_SIZE bytes.
     */
    void get_key_salt(unsigned char *buf) {
        s_lock();
        memcpy(buf, key_salt, CRYPTO_SALT_SIZE);
        s_unlock();
    }

    /*
     * Puts password hash in `buf`.
     *
     * buf must have room for at least CRYPTO_HASH_SIZE bytes.
     */
    void get_password_hash(unsigned char *buf) {
        s_lock();
        memcpy(buf, password_hash, CRYPTO_HASH_SIZE);
        s_unlock();
    }

    /*
     * Initializes pass store crypto-related data structures.
     *
     * Return 0 on success.
     * Return -1 if memory lock fails.
     * Return PASS_STORE_LOCKED is pass store is locked.
     */
    int init_crypto(const unsigned char *key, const unsigned char *salt, const unsigned char *hash) {
        if (check_lock()) {
            return PASS_STORE_LOCKED;
        }

        s_lock();

        memcpy(encryption_key, key, CRYPTO_KEY_SIZE);
        memcpy(key_salt, salt, CRYPTO_SALT_SIZE);
        memcpy(password_hash, hash, CRYPTO_HASH_SIZE);

        if (crypto_memlock(encryption_key, CRYPTO_KEY_SIZE) != 0) {
            s_unlock();
            return -1;
        }

        s_unlock();

        return 0;
    }

    /*
     * Decrypts file contents of size `length` pointed to by `fp` and loads to pass store.
     *
     * Return number of entries loaded on success.
     * Return -1 on out of memory error.
     * Return -2 on decryption error.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int load(ifstream &fp, size_t length) {
        if (check_lock()) {
            return PASS_STORE_LOCKED;
        }

        unsigned long long plain_length = 0;
        unsigned char *plaintext = (unsigned char *) malloc(length + 1);

        if (plaintext == NULL) {
            return -1;
        }

        s_lock();
        int ret = crypto_decrypt_file(fp, length, plaintext, &plain_length, encryption_key);
        s_unlock();

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
        size_t num_entries = load_buffer((char *) plaintext);

        crypto_memwipe(plaintext, plain_length);
        free(plaintext);

        return num_entries;
    }

    /*
     * Encrypts pass store data and saves result to file pointed to by `fp`.
     * fp should be offset to after the plaintext header.
     *
     * Return 0 on success.
     * Return -1 on memory related error.
     * Return -2 if encryption fails.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int save(ofstream &fp) {
        if (check_lock()) {
            return PASS_STORE_LOCKED;
        }

        size_t file_size = size();

        if (file_size == 0) {
            return 0;
        }

        unsigned char *buf_in = (unsigned char *) malloc(file_size);

        if (buf_in == NULL) {
            return -1;
        }

        if (copy((char *) buf_in) != file_size) {
            free(buf_in);
            return -1;
        }

        unsigned long long out_len = 0;

        s_lock();
        int ret = crypto_encrypt_file(fp, buf_in, file_size, &out_len, encryption_key);
        s_unlock();

        if (ret < 0) {
            crypto_memwipe(buf_in, file_size);
            free(buf_in);
            return -2;
        }

        crypto_memwipe(buf_in, file_size);
        free(buf_in);

        return 0;
    }

    /*
     * Securely wipes all sensitive pass store data from memory.
     */
    void clear(void) {
        s_lock();

        crypto_memunlock(encryption_key, CRYPTO_KEY_SIZE);

        for (auto &item: store) {
            string key = item.first;
            crypto_memunlock((unsigned char *) store.at(key)->password, sizeof(store.at(key)->password));
            free(store.at(key));
            store.erase(key);
        }

        s_unlock();
    }

    ~Pass_Store(void) {
        clear();
    }
};

#endif // SPICY
