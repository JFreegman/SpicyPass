/*  spicy.hpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
 */

#ifndef SPICY_H
#define SPICY_H

#if defined(_WIN32)
#define strtok_r strtok_s
#else
#include <SpicyPassConfig.h>
#endif // _WIN32

#include <map>
#include <mutex>
#include <string>

#include "crypto.hpp"
#include "util.hpp"

using namespace std;

/* The maximum number of characters for a pass store entry key/login */
#define MAX_STORE_KEY_SIZE        (256)

/* The maximum number of characters for a pass store entry value/password */
#define MAX_STORE_PASSWORD_SIZE   (256)

/* The minimum number of characters for a master password */
#define MIN_MASTER_PASSWORD_SIZE  (8)

/* The maximum number of characters for a pass store entry note */
#define MAX_STORE_NOTE_SIZE   (5000)

/* Return code indicating that `idle_lock` is set to true */
#define PASS_STORE_LOCKED (INT_MIN)

/* Seconds to wait since last activity before we prompt the user to enter their password again */
#define DEFAULT_IDLE_LOCK_TIMEOUT (60U * 10U)

/* The byte used to separate entry values in file format */
#define DELIMITER "\r"

/* Legacy delimiter is used for all versions <= 0.5.2 */
#define LEGACY_DELIMITER ":"

/*
 * File format version is indicated by the first byte in the pass store file.
 */
enum {
    FILE_FORMAT_VERSION_1       = 0x88U,
    FILE_FORMAT_VERSION_2       = 0x89U,
    FILE_FORMAT_VERSION_CURRENT = 0x90U
};

/*
 * We use this struct to store passwords in the store map so that
 * they can be securely wiped from memory when no longer in use.
 */
struct Password {
    char password[MAX_STORE_PASSWORD_SIZE + 1];
    char note[MAX_STORE_NOTE_SIZE + 1];
};


class Pass_Store
{
public:
    /*
     * Initialize a Pass Store object.
     */
    Pass_Store(void);

    /*
     * Lock and unlock the pass store mutex respectively.
     */
    void s_lock(void);
    void s_unlock(void);

    /*
     * Signals shutdown. This is used to notify threads when it's time to stop.
     */
    void signal_shutdown(void);

    /*
     * Return false if the shutdown signal has been triggered.
     */
    bool running(void);

    /*
     *  Set and get gui status respectively.
     */
    void set_gui_status(bool have_gui);
    bool get_gui_status(void);

    /*
     * Return true if `idle_lock` is enabled. If lock is not enabled,
     * the `last_active` timer is reset.
     *
     * This should be used to block all user-prompted operations when the lock
     * in enabled.
     */
    bool check_lock(void);

    /*
     * Sets `idle_lock` to false and resets the last active timer. This should only
     * be called immediately after the user has entered a valid master password.
     */
    void disable_lock(void);

    /*
     * Polls the `last_active` timer. Upon timeout `idle_lock` is enabled and
     * all pass store functionality is disabled until `disable_lock()` is called.
     */
    void poll_idle(void);

    /*
     * Sets the idle lock timeout. If `timeout` is 0 the idle lock will be disabled.
     */
    void set_idle_timeout(int timeout);

    /*
     * Returns the idle lock timeout value.
     */
    size_t get_idle_timeout(void);

    /*
     * Inserts `key` into pass store with `value` and `note`. If key already exists it will
     * be overwritten.
     *
     * Return 0 on sucess.
     * Return -1 on failure.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int insert(const string &key, const string &pass, const string &note);

    /*
     * Removes `key` from pass store.
     *
     * Return 0 on success.
     * Return -1 if key does not exist.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int remove(const string &key);

    /*
     * Replaces `old_key` with `new_key` and `value`.
     *
     * Return 0 on success.
     * Return -1 if new_key already exists.
     * Return -2 if insert() fails.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int replace(const string &old_key, const string &new_key, const string &password, const string &note);

    /*
     * Return 1 if `key` exists in pass store.
     * Return 0 if key does not exist.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int key_exists(const string &key);

    /*
     * Puts matches for `search_key` in `result`. The first tuple member is the key and
     * the second member is the password. If `exact` is false it will return all partial matches.
     *
     * Note: The second tuple items (passwords) must be locked by the pass store mutex before
     * they are accessed, as they are pointers owned by the pass store object and can theoretically
     * be accessed by other threads.
     *
     * Return 0 on succsess.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int get_matches(const string &search_key, vector<tuple<string, const char *, const char *>> &result, bool exact);

    /*
     * Puts key salt in `buf`.
     *
     * buf must have room for at least CRYPTO_SALT_SIZE bytes.
     */
    void get_key_salt(unsigned char *buf);

    /*
     * Puts password hash in `buf`.
     *
     * buf must have room for at least CRYPTO_HASH_SIZE bytes.
     */
    void get_password_hash(unsigned char *buf);

    /*
     * Validates pass store master password.
     *
     * Return true if password is correct.
     */
    bool validate_password(const unsigned char *password, size_t length);

    /*
     * Initializes pass store crypto-related data structures.
     *
     * Return 0 on success.
     * Return -1 if memory lock fails.
     * Return PASS_STORE_LOCKED is pass store is locked.
     */
    int init_crypto(const unsigned char *key, const unsigned char *salt, const unsigned char *hash);

    /*
     * Decrypts file contents of size `length` pointed to by `fp` and loads to pass store.
     *
     * Return number of entries loaded on success.
     * Return -1 on out of memory error.
     * Return -2 on decryption error.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int load(ifstream &fp, size_t length, unsigned char format_version);

    /*
     * Encrypts pass store data and saves result to file pointed to by `fp`.
     * `fp` should be offset to after the plaintext header.
     *
     * Return 0 on success.
     * Return -1 on memory related error.
     * Return -2 if encryption fails.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int save(ofstream &fp);

    /*
     * Writes pass store contents to a plaintext file.
     *
     * Return 0 on success.
     * Return PASS_STORE_LOCKED if pass store is locked.
     */
    int _export(ofstream &fp);

    /*
     * Sets the save file path to `save_file`. `set_custom_path` should be true
     * if we're using a user-specified path (i.e. non-default).
     */
    void set_save_file(const string &save_file, bool set_custom_path);

    /*
     * Returns the current save file path.
     */
    string get_save_file(void);

    /*
     * Return true if a custom save file has been set by the user.
     */
    bool using_custom_profile(void);

    /*
     * If read only mode is set to true we cannot write to file. This is set when
     * the file lock exists.
     */
    void set_read_only(bool read_only);
    bool get_read_only(void);

    /*
     * Securely wipes all sensitive pass store data from memory.
     */
    void clear(void);

    ~Pass_Store(void);

private:
    map<string, struct Password *> store;

    unsigned char encryption_key[CRYPTO_KEY_SIZE];
    unsigned char key_salt[CRYPTO_SALT_SIZE];
    unsigned char password_hash[CRYPTO_HASH_SIZE];

    string save_file;
    bool custom_profile_set = false;

    // This mutex is responsible for protecting all variables and data stored within the Pass_Store instance.
    mutex store_m;

    bool gui_enabled = false;
    bool idle_lock = false;
    bool shutdown_signal = false;
    bool read_only_mode = false;
    size_t idle_timeout = DEFAULT_IDLE_LOCK_TIMEOUT;
    time_t last_active = get_time();

    /*
     * Returns a string containing a key value entry in file format.
     */
    string format_entry(const string &key, const char *value, const char *note);

    /*
     * Returns the size of the store map in file format.
     */
    size_t size(void);

    /*
     * Copies contents of store map into `buf` in file format.
     *
     * The `size()` method should be used to determine how large the buffer
     * needs to be.
     *
     * Returns the number of bytes copied to the buffer.
     */
    size_t copy(char *buf);

    /*
     * Loads the contents of `buf` into the pass store map. Buffer must be file
     * formatted and null terminated.
     *
     * Returns the number of entries loaded to the store map.
     */
    size_t load_buffer(char *buf, unsigned char format_version);

    /*
     * Deletes entry for `key` from pass store if it exists.
     *
     * This method does not check the idle lock so care must be taken when using it.
     *
     * Return false if key was not found.
     */
    bool delete_entry(const string &key);
};  // class Pass_Store

#endif // SPICY_H
