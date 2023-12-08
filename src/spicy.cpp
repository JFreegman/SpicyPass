/*  spicy.cpp
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

#include <thread>
#include <chrono>

#include <fstream>
#include <iostream>

#include <sys/stat.h>

#include "crypto.hpp"
#include "cli.hpp"
#include "gui.hpp"
#include "password.hpp"
#include "spicy.hpp"

using namespace std;

/* Seconds to wait since last activity before we prompt the user to enter their password again */
#define IDLE_LOCK_TIMEOUT (60U * 10U)


Pass_Store::Pass_Store(void)
{
    memset(encryption_key, 0, sizeof(encryption_key));
    memset(key_salt, 0, sizeof(key_salt));
    memset(password_hash, 0, sizeof(password_hash));
}

void Pass_Store::s_lock(void)
{
    store_m.lock();
}

void Pass_Store::s_unlock(void)
{
    store_m.unlock();
}

void Pass_Store::signal_shutdown(void)
{
    s_lock();
    shutdown_signal = true;
    s_unlock();
}

bool Pass_Store::running(void)
{
    s_lock();
    bool is_running = !shutdown_signal;
    s_unlock();

    return is_running;
}

void Pass_Store::set_gui_status(bool have_gui)
{
    s_lock();
    gui_enabled = have_gui;
    s_unlock();
}

bool Pass_Store::get_gui_status(void)
{
    s_lock();
    bool enabled = gui_enabled;
    s_unlock();

    return enabled;
}

bool Pass_Store::check_lock(void)
{
    s_lock();

    if (idle_lock) {
        s_unlock();
        return true;
    }

    last_active = get_time();
    s_unlock();

    return false;
}

void Pass_Store::disable_lock(void)
{
    s_lock();

    idle_lock = false;
    last_active = get_time();

    s_unlock();
}

void Pass_Store::poll_idle(void)
{
    s_lock();

    if (idle_lock) {
        s_unlock();
        return;
    }

    if (!timed_out(last_active, IDLE_LOCK_TIMEOUT)) {
        s_unlock();
        return;
    }

    idle_lock = true;

    s_unlock();

    if (!get_gui_status()) {
        clear_console();
        cout << "Idle lock has been activated. Press enter to unlock." << endl;
    }

    clear();
}

int Pass_Store::insert(const string &key, const string &value)
{
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
    delete_entry(key);

    s_lock();

    try {
        store.insert({key, pass});
    } catch (const exception &e) {
        free(pass);
        s_unlock();
        cerr << "Caught exception in insert(): " << e.what() << endl;
        return -1;
    }

    s_unlock();

    return 0;
}

int Pass_Store::remove(const string &key)
{
    if (check_lock()) {
        return PASS_STORE_LOCKED;
    }

    if (!delete_entry(key)) {
        return -1;
    }

    return 0;
}

int Pass_Store::replace(const string &old_key, const string &new_key, const string &value)
{
    if (check_lock()) {
        return PASS_STORE_LOCKED;
    }

    bool keys_are_same = old_key == new_key;

    s_lock();

    if (!keys_are_same) {
        bool new_exists = store.find(new_key) != store.end();

        if (new_exists) {
            s_unlock();
            return -1;
        }
    }

    s_unlock();

    if (insert(new_key, value) != 0) {
        return -2;
    }

    if (!keys_are_same) {
        delete_entry(old_key);
    }

    return 0;
}

int Pass_Store::key_exists(const string &key)
{
    if (check_lock()) {
        return PASS_STORE_LOCKED;
    }

    s_lock();
    bool exists = store.find(key) != store.end();
    s_unlock();

    return exists ? 1 : 0;
}

int Pass_Store::get_matches(const string &search_key, vector<tuple<string, const char *>> &result, bool exact)
{
    if (check_lock()) {
        return PASS_STORE_LOCKED;
    }

    s_lock();

    if (exact) {
        for (const auto &[key, value] : store) {
            if (search_key == key) {
                result.push_back({key, value->password});
                break;
            }
        }
    } else {
        for (const auto &[key, value] : store) {
            if (search_key.compare(0, search_key.length(), key, 0, search_key.length()) == 0) {
                result.push_back({key, value->password});
            }
        }
    }

    s_unlock();

    return 0;
}

void Pass_Store::get_key_salt(unsigned char *buf)
{
    s_lock();
    memcpy(buf, key_salt, CRYPTO_SALT_SIZE);
    s_unlock();
}

void Pass_Store::get_password_hash(unsigned char *buf)
{
    s_lock();
    memcpy(buf, password_hash, CRYPTO_HASH_SIZE);
    s_unlock();
}

bool Pass_Store::validate_password(const unsigned char *password, size_t length)
{
    if (length > MAX_STORE_PASSWORD_SIZE) {
        return false;
    }

    unsigned char hash[CRYPTO_HASH_SIZE];
    get_password_hash(hash);

    return crypto_verify_pass_hash(hash, password, length);
}

int Pass_Store::init_crypto(const unsigned char *key, const unsigned char *salt, const unsigned char *hash)
{
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

int Pass_Store::load(ifstream &fp, size_t length, unsigned char format_version)
{
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
                cerr << "Decryption failed: Out of memory" << endl;
                return -2;
            }

            case -2: {
                cerr << "Decryption failed: Corrupt file or bad key" << endl;
                return -2;
            }

            case -3: {
                cerr << "Decryption failed: File corrupt" << endl;
                return -2;
            }

            default: {
                return -2;
            }
        }
    }

    plaintext[plain_length] = 0;
    size_t num_entries = load_buffer((char *) plaintext, format_version);

    crypto_memwipe(plaintext, plain_length);
    free(plaintext);

    return num_entries;
}

int Pass_Store::save(ofstream &fp)
{
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

    crypto_memwipe(buf_in, file_size);
    free(buf_in);

    if (ret < 0) {
        return -2;
    }

    return 0;
}

int Pass_Store::_export(ofstream &fp)
{
    if (check_lock()) {
        return PASS_STORE_LOCKED;
    }

    for (const auto &[key, value] : store) {
        fp << key << endl << value->password << endl << endl;
    }

    return 0;
}

void Pass_Store::clear(void)
{
    s_lock();

    crypto_memunlock(encryption_key, CRYPTO_KEY_SIZE);

    for (const auto &[key, value] : store) {
        crypto_memunlock((unsigned char *) value->password, sizeof(value->password));
        free(store.at(key));
    }

    store.clear();

    s_unlock();
}

Pass_Store::~Pass_Store(void)
{
    clear();
}

string Pass_Store::format_entry(const string &key, const char *value)
{
    return key + DELIMITER + value + '\n';
}

size_t Pass_Store::size(void)
{
    size_t size = 0;

    s_lock();

    for (const auto &[key, value] : store) {
        string entry = format_entry(key, value->password);
        size += entry.length();
    }

    s_unlock();

    return size;
}

size_t Pass_Store::copy(char *buf)
{
    size_t pos = 0;

    s_lock();

    for (const auto &[key, value] : store) {
        string entry = format_entry(key, value->password);
        memcpy(buf + pos, entry.c_str(), entry.length());
        pos += entry.length();
    }

    s_unlock();

    return pos;
}

size_t Pass_Store::load_buffer(char *buf, unsigned char format_version)
{
    const char *delimiter = (format_version == FILE_FORMAT_VERSION_1) ? LEGACY_DELIMITER : DELIMITER;
    size_t count = 0;
    char *s = NULL;
    char *t = strtok_r((char *) buf, "\n", &s);

    while (t) {
        string entry = t;
        auto d = entry.find(delimiter);

        if (d != string::npos) {
            string key = entry.substr(0, d);
            string pass = entry.substr(d + 1, entry.length());

            if (insert(key, pass) != 0) {
                cerr << "Warning: Failed to load entry with key `" << key << "`" << endl;
                continue;
            }

            ++count;
        }

        t = strtok_r(NULL, "\n", &s);
    }

    return count;
}

bool Pass_Store::delete_entry(const string &key)
{
    s_lock();

    bool exists = store.find(key) != store.end();

    if (exists) {
        crypto_memunlock((unsigned char *) store.at(key)->password, sizeof(store.at(key)->password));
        free(store.at(key));
        store.erase(key);
    }

    s_unlock();

    return exists;
}


static void print_usage_exit(void)
{
    cout << "Usage: spicypass [--gui | --cli]" << endl;
    exit(-1);
}

static void print_version(const char *binary_name)
{
#ifndef _WIN32
    cout << binary_name << " version "
         << SpicyPass_VERSION_MAJOR << "."
         << SpicyPass_VERSION_MINOR << "."
         << SpicyPass_VERSION_PATCH << endl;
#endif // _WIN32
}

static void store_lock_loop(Pass_Store &p)
{
    while (p.running()) {
        p.poll_idle();
        this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

/*
 * Return true if the --gui option is set.
 */
static bool gui_enabled(int argc, char **argv)
{
    if (argc <= 1) {
        return true;
    }

    if (strcmp(argv[1], "--cli") == 0) {
        return false;
    }

    if (strcmp(argv[1], "--gui") != 0) {
        print_usage_exit();
    }

    return true;
}

static void set_file_permissions(void)
{
#ifndef _WIN32
    umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
#endif
}

int main(int argc, char **argv)
{
    print_version(argv[0]);

#if GUI_SUPPORT
    bool have_gui = gui_enabled(argc, argv);
    GUI ui;
#else

    if (argc > 1) {
        cerr << "Warning: Unrecognized options" << endl;
    }

    bool have_gui = false;
#endif // GUI_SUPPORT

    set_file_permissions();

    if (crypto_init() != 0) {
        cerr << "crypto_init() failed" << endl;
        return -1;
    }

    Pass_Store p;
    p.set_gui_status(have_gui);

    int ret = -1;

    if (have_gui) {
        ret = 0;
    } else {
        ret = cli_new_pass_store(p);
    }

    switch (ret) {
        case 0: {
            break;
        }

        case -2: {
            cerr << "crypto_memlock() failed in new_pass_store()" << endl;
            return -1;
        }

        case -3: {
            cerr << "load_password_store() failed to open pass store file" << endl;
            return -1;
        }

        case -4: {
            cout << "Invalid password" << endl;
            return -1;
        }

        case -5: {
            cerr << "Failed to decrypt pass store file" << endl;
            return -1;
        }

        case -6: {
            cerr << "GUI failed to initialize" << endl;
            return -1;
        }

        default: {
            cerr << "Unknown error" << endl;
            return -1;
        }
    }

    thread t(store_lock_loop, ref(p));

    if (have_gui) {
#ifdef GUI_SUPPORT
        gtk_init(&argc, &argv);
        ui.run(p);
#endif
    } else {
        run_cli(p);
    }

    p.signal_shutdown();

    t.join();

    return 0;
}
