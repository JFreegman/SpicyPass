/*  load.hpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
 */

#ifndef LOAD_H
#define LOAD_H

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif // _WIN32

#include "spicy.hpp"
#include "crypto.hpp"

#define PASS_STORE_HEADER_SIZE (CRYPTO_HASH_SIZE + CRYPTO_SALT_SIZE + 1)

#define DEFAULT_FILENAME ".spicypass"
#define LOCK_FILENAME    ".~spicylock~"
#define EXPORT_FILE_EXTENTION ".spicy_export"

/*
 * Returns a string containing the file path for `filename`
 * in the home directory.
 *
 * If `custom_path` is true we don't use the home directory as the path base.
 * If `temp` is true we append a tmp file extention to the file name.
 */
const string get_store_path(const string &filename, bool temp, bool custom_path);

/*
 * Attempts to validate password, decrypt password store, and load it into `p`.
 *
 * Return the number of pass store entries loaded on success.
 * Return -1 on file related error.
 * Return -2 if password is invalid.
 * Return -3 on crypto related error.
 * Return -4 on bad file format.
 */
int load_password_store(Pass_Store &p, const unsigned char *password, size_t length);

/*
 * Saves encrypted contents of pass store to disk.
 *
 * This function is atomic: changes will only be made to the pass store file upon success.
 *
 * Return 0 on success.
 * Return -1 if path is invalid.
 * Return -2 if file encryption fails.
 * Return -3 if file save operation fails.
 * Return -4 if read only mode is enabled.
 */
int save_password_store(Pass_Store &p);

/*
 * Return 1 if pass_store file does not exist or is empty.
 * Return 0 if pass_store file exists.
 * Return -1 if invalid path.
 * Return -2 if file cannot be opened.
 */
int first_time_run(Pass_Store &p);

/*
 * Adds a header to the beginning of pass store file.
 *
 * This function should only be called when the pass store file is empty.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int init_pass_hash(Pass_Store &p, const unsigned char *password, size_t length);

/*
 * Initializes `p` with a new encryption key derived from `password`, as well as a
 * new key salt and password hash. Changes are written to file.
 *
 * Return 0 on sucess.
 * Return -1 on crypto related error.
 * Return -2 if `p` fails to update.
 * Return -3 on save failure.
 * Return -4 if read only mode is enabled.
 * Return PASS_STORE_LOCKED if pass store is locked.
 */
int update_crypto(Pass_Store &p, const unsigned char *password, size_t length);

/*
 * Writes contents of pass store to a plaintext file at `export_path`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int export_pass_store_to_plaintext(Pass_Store &p, const string &export_path);

/*
 * Returns a string containing export file path.
 */
string get_export_path(void);

/*
 * Deletes the file lock. Called on exit.
 *
 * Return false on error.
 */
bool delete_file_lock(Pass_Store &p);

/*
 * Creates file lock. Called before any other file operations.
 *
 * Return false on file creation error.
 */
bool create_file_lock(Pass_Store &p);

/*
 * Return true if the spicypass file lock exists.
 */
bool file_lock_exists(void);

/* Returns the file lock path. */
const string get_lock_path(void);

#endif // LOAD_H
