/*  load.cpp
 *
 *
 *  Copyright (C) 2019 Jfreegman <Jfreegman@gmail.com>
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

#include "load.hpp"
#include "crypto.hpp"

using namespace std;

#define DEFAULT_FILENAME ".based_store"

#define MAGIC_NUMBER (0x88U)
#define PASS_STORE_HEADER_SIZE (CRYPTO_HASH_SIZE + CRYPTO_SALT_SIZE + 1)

static const string get_store_path(void)
{
    struct passwd *pw = getpwuid(getuid());

    if (!pw) {
        return "";
    }

    string homedir = string(pw->pw_dir);
    string path = homedir + "/" + DEFAULT_FILENAME;

    return path;
}

/*
 * Opens input stream for the pass_store file.
 *
 * Returns 0 on success.
 * Return -1 if invalid path.
 * Return -2 if file cannot be opened.
 */
static int get_pass_store_if(ifstream &fp)
{
    const string path = get_store_path();

    if (path == "") {
        return -1;
    }

    try {
        fp.open(path);
        return 0;
    }
    catch (const exception &) {
        return -2;
    }
}

/*
 * Opens output stream for the pass_store file.
 *
 * Return 0 on success.
 * Return -1 if invalid path.
 * Return -2 if file cannot be opened.
 */
static int get_pass_store_of(ofstream &fp)
{
    const string path = get_store_path();

    if (path == "") {
        return -1;
    }

    try {
        fp.open(path);
        return 0;
    }
    catch (const exception &) {
        return -2;
    }
}

/*
 * Writes header to `fp`. fp should be pointing to the beginning of the file.
 */
static void write_header(ofstream &fp, const unsigned char *hash, const unsigned char *salt)
{
    unsigned char m = MAGIC_NUMBER;
    fp.write((const char *) &m, sizeof(unsigned char));
    fp.write((char *) hash, CRYPTO_HASH_SIZE);
    fp.write((char *) salt, CRYPTO_SALT_SIZE);
}

/*
 * Reads header from `fp` and places results in respective buffers. fp should be pointing to
 * the beginning of the file.
 */
static void read_header(ifstream &fp, unsigned char *magic_number, unsigned char *hash, unsigned char *salt)
{
    fp.read((char *) magic_number, sizeof(unsigned char));
    fp.read((char *) hash, CRYPTO_HASH_SIZE);
    fp.read((char *) salt, CRYPTO_SALT_SIZE);
}

/*
 * Attempts to validate password, decrypt password store, and load it to memory.
 *
 * Return 0 on success.
 * Return -1 on file related error.
 * Return -2 if password is invalid.
 * Return -3 on crypto related error.
 * Return -4 if memory lock fails.
 * Return -5 if magic number is wrong.
 */
int load_password_store(Pass_Store &p, const unsigned char *password, size_t length)
{
    ifstream fp;

    if (get_pass_store_if(fp) != 0) {
        return -1;
    }

    unsigned char magic_number;
    unsigned char hash[CRYPTO_HASH_SIZE];
    unsigned char salt[CRYPTO_SALT_SIZE];
    read_header(fp, &magic_number, hash, salt);

    if (magic_number != MAGIC_NUMBER) {
        fp.close();
        return -5;
    }

    if (!crypto_verify_pass_hash(hash, password, length)) {
        fp.close();
        return -2;
    }

    unsigned char encryption_key[CRYPTO_KEY_SIZE];

    if (crypto_derive_key_from_pass(encryption_key, CRYPTO_KEY_SIZE, password, length, salt) != 0) {
        cout << "crypto_derive_key_from_pass() failed" << endl;
        fp.close();
        return -3;
    }

    if (crypto_memlock(encryption_key, CRYPTO_KEY_SIZE) != 0) {
        cout << "crypto_memlock() failed in load_password_store()" << endl;
        fp.close();
        return -4;
    }

    if (p.init_crypto(encryption_key, salt, hash) != 0) {
        cout << "crypto_memlock() failed in init_crypto()" << endl;
        fp.close();
        return -4;
    }

    if (crypto_memunlock(encryption_key, CRYPTO_KEY_SIZE) != 0) {
        cout << "Warning: crypto_memunlock() failed in load_password_store()" << endl;
    }

    const string path = get_store_path();
    off_t file_length = file_size(path.c_str());

    if (file_length < PASS_STORE_HEADER_SIZE) {
        cout << "Invalid file format" << endl;
        fp.close();
        return -1;
    }

    if (file_length > PASS_STORE_HEADER_SIZE) {
        if (p.load(fp, file_length - PASS_STORE_HEADER_SIZE) != 0) {
            fp.close();
            return -3;
        }
    }

    fp.close();

    return 0;
}

/*
 * Return 1 if based_store file does not exist or is empty.
 * Return 0 if based_store file exists.
 * Return -1 if invalid path.
 * Return -2 if file cannot be opened.
 */
int first_time_run(void)
{
    ifstream fp;
    int ret = get_pass_store_if(fp);

    if (ret != 0) {
        return ret;
    }

    int empty = file_is_empty(fp) ? 1 : 0;
    fp.close();

    return empty;
}

/*
 * Puts hash of `password` at the beginning of based store file.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int init_pass_hash(const unsigned char *password, size_t length)
{
    unsigned char hash[CRYPTO_HASH_SIZE];

    if (crypto_make_pass_hash(hash, password, length) != 0) {
        cout << "crypto_make_pass_hash() failed." << endl;
        return -1;
    }

    unsigned char salt[CRYPTO_SALT_SIZE];
    crypto_gen_salt(salt, CRYPTO_SALT_SIZE);

    ofstream fp;
    int ret = get_pass_store_of(fp);

    if (ret != 0) {
        return ret;
    }

    write_header(fp, hash, salt);
    fp.close();

    return 0;
}

/*
 * Saves encrypted contents of pass store to disk.
 *
 * Return 0 on success.
 * Return -1 if path is invalid.
 * Return -2 if file encryption fails.
 */
int save_password_store(Pass_Store &p)
{
    const string path = get_store_path();

    if (path == "") {
        return -1;
    }

    ofstream fp;

    try {
        fp.open(path);
    }
    catch (const exception &) {
        return -1;
    }

    unsigned char salt[CRYPTO_SALT_SIZE];
    p.get_key_salt(salt);

    unsigned char hash[CRYPTO_HASH_SIZE];
    p.get_password_hash(hash);

    write_header(fp, hash, salt);

    if (p.save(fp) != 0) {
        fp.close();
        return -2;
    }

    fp.close();

    return 0;
}