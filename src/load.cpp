/*  load.cpp
 *
 *
 *  Copyright (C) 2020-2024 Jfreegman <Jfreegman@gmail.com>
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

#include <cassert>
#include <filesystem>

#include <errno.h>
#include <sys/types.h>

#include "load.hpp"

using namespace std;

/*
 * Return true if `format_version` matches a known file format version.
 */
static bool valid_format_version(unsigned char format_version)
{
    return format_version >= FILE_FORMAT_VERSION_1 && format_version <= FILE_FORMAT_VERSION_CURRENT;
}

const string get_store_path(const string &filename, bool temp, bool custom_path)
{
    string path;

    if (!custom_path) {
#if defined(_WIN32)
        const string homedir = getenv("HOMEPATH");
        path = homedir + "\\" + filename;
#else
        char buf[1024];
        struct passwd pwd;
        struct passwd *result;

        const int ret = getpwuid_r(getuid(), &pwd, buf, sizeof(buf), &result);

        if (ret != 0) {
            cerr << "getpwuid_r() failed with error code: " << to_string(ret) << endl;
            return "";
        };

        const string homedir = string(pwd.pw_dir);

        path = homedir + "/" + filename;

#endif // _WIN_32
    } else {
        path = filename;
    }

    if (temp) {
        path += ".tmp";
    }

    return path;
}

const string get_lock_path(void)
{
    return get_store_path(LOCK_FILENAME, false, false);
}

/*
 * Opens input stream for the pass store file.
 *
 * Returns 0 on success.
 * Return -1 if invalid path.
 * Return -2 if file cannot be opened.
 */
static int get_pass_store_if(Pass_Store &p, ifstream &fp, const string &save_file)
{
    const string path = get_store_path(save_file, false, p.using_custom_profile());

    if (path.empty()) {
        return -1;
    }

    try {
        fp.open(path, ios::binary);
        return 0;
    } catch (const exception &e) {
        cerr << "Caught exception in get_pass_store_if(): " << e.what() << endl;
        return -2;
    }
}

/*
 * Opens output stream for the pass store file.
 *
 * Set `temp` to true for temp file instead. The temp file is used for
 * all writing operations outside of the initialization of a profile.
 *
 * Return 0 on success.
 * Return -1 if invalid path.
 * Return -2 if file cannot be opened.
 */
static int get_pass_store_of(Pass_Store &p, ofstream &fp, bool temp)
{
    const string path = get_store_path(p.get_save_file(), temp, p.using_custom_profile());

    if (path.empty()) {
        return -1;
    }

    try {
        fp.open(path, ios::binary);
        return 0;
    } catch (const exception &e) {
        cerr << "Caught exception in get_pass_store_of(): " << e.what() << endl;
        return -2;
    }
}

/*
 * Writes header to `fp`.
 *
 * Return 0 on success.
 * Return -1 on write fail or if file stream is not at the beginning of the file.
 */
static int write_header(ofstream &fp, const unsigned char *hash, const unsigned char *salt)
{
    if (fp.tellp() != 0) {
        return -1;
    }

    unsigned char m = FILE_FORMAT_VERSION_CURRENT;
    fp.write((char *) &m, sizeof(unsigned char));
    fp.write((char *) hash, CRYPTO_HASH_SIZE);
    fp.write((char *) salt, CRYPTO_SALT_SIZE);

    if (fp.tellp() != PASS_STORE_HEADER_SIZE) {
        return -1;
    }

    return 0;
}

/*
 * Reads header from `fp` and places results in respective buffers. fp should be pointing to
 * the beginning of the file.
 *
 * Return 0 on succes.
 * Return -1 on read fail or if file stream is not at the beginning of file.
 */
static int read_header(ifstream &fp, unsigned char *format_version, unsigned char *hash, unsigned char *salt)
{
    if (fp.tellg() != 0) {
        return -1;
    }

    fp.read((char *) format_version, sizeof(unsigned char));

    if (!fp) {
        return -1;
    }

    fp.read((char *) hash, CRYPTO_HASH_SIZE);

    if (!fp) {
        return -1;
    }

    fp.read((char *) salt, CRYPTO_SALT_SIZE);

    if (!fp) {
        return -1;
    }

    if (fp.tellg() != PASS_STORE_HEADER_SIZE) {
        return -1;
    }

    return 0;
}

int save_password_store(Pass_Store &p)
{
    if (p.get_read_only()) {
        return -4;
    }

    ofstream fp;
    get_pass_store_of(p, fp, true);

    unsigned char salt[CRYPTO_SALT_SIZE];
    p.get_key_salt(salt);

    unsigned char hash[CRYPTO_HASH_SIZE];
    p.get_password_hash(hash);

    if (write_header(fp, hash, salt) != 0) {
        return 0;
    }

    if (p.save(fp) != 0) {
        fp.close();
        return -2;
    }

    fp.close();

    string temp_path = get_store_path(p.get_save_file(), true, p.using_custom_profile());
    string real_path = get_store_path(p.get_save_file(), false, p.using_custom_profile());

    if (temp_path.empty() || real_path.empty()) {
        return -1;
    }

    if (rename(temp_path.c_str(), real_path.c_str()) != 0) {
        if (errno != EEXIST) {
            remove_file(temp_path);
            return -3;
        }

        string tmp = real_path + ".tmp.1";

        if (rename(real_path.c_str(), tmp.c_str()) != 0) {
            remove_file(temp_path);
            return -3;
        }

        if (rename(temp_path.c_str(), real_path.c_str()) != 0) {
            cerr << "rename() failed in save_password_store() with errno code: " << to_string(errno) << endl;

            // If we get here we're in trouble. The best we can do is attempt
            // to fall back to original file and clean everything up.
            if (rename(tmp.c_str(), real_path.c_str()) != 0) {
                remove_file(tmp);
            }

            remove_file(temp_path);
            return -3;
        }

        remove_file(tmp);
    }

    return 0;
}

/*
 * Initializes `params` structure with the relevant parameters from the `hash` string.
 *
 * Expects a hash produced by `crypto_pwhash_str()`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int get_hash_params(const string &hash, Hash_Parameters *params)
{
    auto tokens = string_split(hash, "$");

    for (auto &tok : tokens) {
        if (string_contains(tok, "argon")) {
            if (tok == "argon2id") {
                params->algorithm = crypto_pwhash_ALG_ARGON2ID13;
            } else if (tok == "argon2i") {
                params->algorithm = crypto_pwhash_ALG_ARGON2I13;
            } else {
                params->algorithm = crypto_pwhash_ALG_DEFAULT;
            }
        } else if (string_contains(tok, "m=")) {
            auto p = string_split(tok, ",");

            try {  // If we got to this point the hash should be valid, but just in case
                string m_tok = p.at(0);
                string t_tok = p.at(1);
                string m_val = m_tok.substr(2, m_tok.length());
                string t_val = t_tok.substr(2, t_tok.length());
                params->memory_limit = stoull(m_val) * 1024U;
                params->ops_limit = stoull(t_val);
            } catch (const exception &e) {
                cerr << "Caught exception in get_hash_params(): " << e.what() << endl;
                return -1;
            }
        }
    }

    if (params->algorithm == 0 || params->memory_limit == 0 || params->ops_limit == 0) {
        return -1;
    }

    return 0;
}

int load_password_store(Pass_Store &p, const unsigned char *password, size_t length)
{
    ifstream fp;

    if (get_pass_store_if(p, fp, p.get_save_file()) != 0) {
        return -1;
    }

    unsigned char format_version;
    unsigned char hash[CRYPTO_HASH_SIZE];
    unsigned char salt[CRYPTO_SALT_SIZE];

    if (read_header(fp, &format_version, hash, salt) != 0) {
        return -1;
    }

    if (!valid_format_version(format_version)) {
        fp.close();
        return -4;
    }

    if (!crypto_verify_pass_hash(hash, password, length)) {
        fp.close();
        return -2;
    }

    p.disable_lock();

    Hash_Parameters params;
    memset(&params, 0, sizeof(params));

    if (get_hash_params(string((char *) hash), &params) != 0) {
        cerr << "Failed to parse hash parameters" << endl;
        return -4;
    }

    unsigned char encryption_key[CRYPTO_KEY_SIZE];

    if (crypto_derive_key_from_pass(encryption_key, CRYPTO_KEY_SIZE, password, length, salt, &params) != 0) {
        cerr << "crypto_derive_key_from_pass() failed" << endl;
        fp.close();
        return -3;
    }

    if (p.init_crypto(encryption_key, salt, hash) != 0) {
        cerr << "crypto_memlock() failed in init_crypto()" << endl;
        fp.close();
        return -3;
    }

    crypto_memwipe(encryption_key, sizeof(encryption_key));

    const string path = get_store_path(p.get_save_file(), false, p.using_custom_profile());
    const off_t file_length = file_size(path.c_str());

    if (file_length < PASS_STORE_HEADER_SIZE) {
        cerr << "Invalid file format" << endl;
        fp.close();
        return -1;
    }

    int num_entries = 0;

    if (file_length > PASS_STORE_HEADER_SIZE) {
        num_entries = p.load(fp, file_length - PASS_STORE_HEADER_SIZE, format_version);

        assert(num_entries != PASS_STORE_LOCKED);

        if (num_entries < 0) {
            fp.close();
            return -3;
        }
    }

    fp.close();

    return num_entries;
}

int first_time_run(Pass_Store &p)
{
    ifstream fp;
    const int ret = get_pass_store_if(p, fp, p.get_save_file());

    if (ret != 0) {
        return ret;
    }

    const int empty = file_is_empty(fp) ? 1 : 0;
    fp.close();

    return empty;
}

int init_pass_hash(Pass_Store &p, const unsigned char *password, size_t length)
{
    unsigned char hash[CRYPTO_HASH_SIZE] = {0};

    if (crypto_make_pass_hash(hash, password, length) != 0) {
        cerr << "crypto_make_pass_hash() failed." << endl;
        return -1;
    }

    unsigned char salt[CRYPTO_SALT_SIZE];
    crypto_gen_salt(salt);

    ofstream fp;
    const int ret = get_pass_store_of(p, fp, false);

    if (ret != 0) {
        return ret;
    }

    if (write_header(fp, hash, salt) != 0) {
        return -1;
    }

    fp.close();

    return 0;
}

int update_crypto(Pass_Store &p, const unsigned char *password, size_t length)
{
    if (p.get_read_only()) {
        cerr << "Cannot change the password in read-only mode." << endl;
        return -4;
    }

    unsigned char encryption_key[CRYPTO_KEY_SIZE];
    unsigned char salt[CRYPTO_SALT_SIZE];
    unsigned char hash[CRYPTO_HASH_SIZE] = {0};

    if (crypto_make_pass_hash(hash, password, length) != 0) {
        cerr << "crypto_make_pass_hash() failed." << endl;
        return -1;
    }

    Hash_Parameters params;
    memset(&params, 0, sizeof(params));

    if (get_hash_params(string((char *) hash), &params) != 0) {
        cerr << "Failed to parse hash parameters" << endl;
        return -1;
    }

    crypto_gen_salt(salt);

    if (crypto_derive_key_from_pass(encryption_key, CRYPTO_KEY_SIZE, password, length, salt, &params) != 0) {
        cerr << "crypto_derive_key_from_pass() failed" << endl;
        return -1;
    }

    const int ret = p.init_crypto(encryption_key, salt, hash);

    crypto_memwipe(encryption_key, sizeof(encryption_key));

    if (ret == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    if (ret != 0) {
        return -2;
    }

    if (save_password_store(p) != 0) {
        return -3;
    }

    return 0;
}

/*
 * Opens output stream for the export file.
 *
 * Return 0 on success.
 * Return -1 if invalid path.
 * Return -2 if file cannot be opened.
 */
static int get_export_of(const string &export_path, ofstream &fp)
{
    if (export_path.empty()) {
        cerr << "Error: Export path is empty." << endl;
        return -1;
    }

    try {
        fp.open(export_path);
        return 0;
    } catch (const exception &e) {
        cerr << "Caught exception in get_export_of(): " << e.what() << endl;
        return -2;
    }
}

int export_pass_store_to_plaintext(Pass_Store &p, const string &export_path)
{
    ofstream fp;

    if (get_export_of(export_path, fp) != 0) {
        return -1;
    }

    if (p._export(fp) != 0) {
        return -1;
    }

    fp.close();

    return 0;
}

bool delete_file_lock(Pass_Store &p)
{
    if (p.get_read_only()) {
        return true;
    }

    const string lock_path = get_lock_path();

    if (lock_path.empty()) {
        return false;
    }

    try {
        filesystem::remove(lock_path);
        return true;
    } catch (const exception &e) {
        cerr << "Caught exception in delete_file_lock(): " << e.what() << endl;
        return false;
    }
}

bool create_file_lock(Pass_Store &p)
{
    if (p.get_read_only()) {
        return true;
    }

    const string lock_path = get_lock_path();

    if (lock_path.empty()) {
        return false;
    }

    ofstream fp;

    try {
        fp.open(lock_path);
        fp.close();
        return true;
    } catch (const exception &e) {
        cerr << "Caught exception in create_file_lock(): " << e.what() << endl;
        return false;
    }
}

bool file_lock_exists(void)
{
    const string lock_path = get_lock_path();

    if (lock_path.empty()) {
        return false;
    }

    ifstream fp(lock_path);
    return fp.good();
}
