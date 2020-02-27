/*  based.cpp
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

#include <BasedPassConfig.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "load.hpp"
#include "password.hpp"
#include "based.hpp"
#include "util.hpp"
#include "crypto.hpp"

using namespace std;


/* Promps password and puts it in `password` array.
 *
 * Return 0 on success.
 * Return -1 input is invalid.
 */
static int prompt_password(unsigned char *password, size_t max_length)
{
    cout << "Enter password: ";

    char pass_buf[MAX_STORE_PASSWORD_SIZE + 1];
    const char *input = fgets(pass_buf, sizeof(pass_buf), stdin);

    if (input == NULL) {
        cout << "Invalid input." << endl;
        return -1;
    }

    size_t pass_length = strlen(pass_buf);

    if (pass_length > max_length) {
        return -1;
    }

    memcpy(password, pass_buf, pass_length);
    password[pass_length] = 0;

    crypto_memwipe((unsigned char *) pass_buf, sizeof(pass_buf));

    return 0;
}

static void new_password_prompt(unsigned char *password, size_t max_length)
{
    while (true) {
        cout << "Enter password: ";

        char pass1[MAX_STORE_PASSWORD_SIZE + 1];
        char pass2[MAX_STORE_PASSWORD_SIZE + 1];

        const char *input1 = fgets(pass1, sizeof(pass1), stdin);

        if (input1 == NULL) {
            cout << "Invalid input." << endl;
            continue;
        }

        size_t pass_length = strlen(pass1);

        if (pass_length < MIN_STORE_PASSWORD_SIZE || pass_length > max_length) {
            cout << "Password must be between " << MIN_STORE_PASSWORD_SIZE  << " and " << max_length << " characters long." << endl;
            continue;
        }

        cout << "Enter password again: ";

        const char *input2 = fgets(pass2, sizeof(pass2), stdin);

        if (input2 == NULL) {
            cout << "Invalid input." << endl;
            continue;
        }

        if (strcmp(pass1, pass2) != 0) {
            cout << "Passwords don't match. Try again." << endl;
            continue;
        }

        memcpy(password, pass1, pass_length);
        password[pass_length] = 0;

        crypto_memwipe((unsigned char *) pass1, sizeof(pass1));
        crypto_memwipe((unsigned char *) pass2, sizeof(pass2));

        return;
    }
}

/*
 * Initializes pass store file with password hash on first run. Puts new password in
 * the `password` buffer.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int init_new_password(unsigned char *password, size_t max_length)
{
    struct termios oflags;
    if (disable_terminal_echo(&oflags) != 0) {
        cout << "Warning: failed to disable terminal echo" << endl;
    }

    new_password_prompt(password, max_length);
    enable_terminal_echo(&oflags);

    if (init_pass_hash(password, strlen((char *) password)) != 0) {
        cout << "init_pass_hash() failed." << endl;
        return -1;
    }

    return 0;
}

/*
 * Prompts user to update password for pass store file.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int change_password_prompt(Pass_Store &p)
{
    unsigned char new_password[MAX_STORE_PASSWORD_SIZE + 1];
    unsigned char hash[CRYPTO_HASH_SIZE];
    p.get_password_hash(hash);

    cout << "Changing master password. Enter q to go back." << endl;

    while (true) {
        cout << "Enter old password: ";

        char old_pass[MAX_STORE_PASSWORD_SIZE + 1];
        const char *input1 = fgets(old_pass, sizeof(old_pass), stdin);

        if (input1 == NULL) {
            cout << "Invalid input" << endl;
            continue;
        }

        if (strcmp(old_pass, "q\n") == 0) {
            return -1;
        }

        size_t pass_length = strlen(old_pass);

        if (!crypto_verify_pass_hash(hash, (unsigned char *) old_pass, pass_length)) {
            cout << "Invalid password" << endl;
            continue;
        }

        break;
    }

    new_password_prompt(new_password, MAX_STORE_PASSWORD_SIZE);
    int ret = update_crypto(p, new_password, strlen((char *) new_password));

    if (ret < 0) {
        cout << "Failed to update password with error: " << to_string(ret) << endl;
        return -1;
    }

    cout << "Successfully updated password" << endl;

    crypto_memwipe(new_password, sizeof(new_password));

    return 0;
}

static int new_password(Pass_Store &p)
{
   struct termios oflags;

    if (disable_terminal_echo(&oflags) != 0) {
        cout << "Warning: failed to disable terminal echo" << endl;
    }

    int ret = change_password_prompt(p);

    enable_terminal_echo(&oflags);

    return ret;
}

static void add(Pass_Store &p)
{
    string key, password;

    cout << "Enter key to add: ";
    getline(cin, key);

    if (key.length() > MAX_ENTRY_KEY_SIZE) {
        cout << "Key is too long" << endl;
        return;
    }

    if (key.length() == 0) {
        cout << "Invalid key" << endl;
        return;
    }

    if (string_contains(key, DELIMITER)) {
        cout << "Key may not contain the \"" << DELIMITER << "\" character" << endl;
        return;
    }

    cout << "Enter password (leave empty for a random password): ";
    getline(cin, password);

    if (password.length() > MAX_STORE_PASSWORD_SIZE) {
        cout << "Password length must not exceed " << to_string(MAX_STORE_PASSWORD_SIZE) << " characters" << endl;
        return;
    }

    if (password.empty()) {
        password = random_password(16U);
    }

    if (password.empty()) {
        cout << "Failed to add entry" << endl;
        return;
    }

    if (p.key_exists(key)) {
        while (true) {
            string s;
            cout << "Key \"" << key << "\" already exists. Overwrite? Y/n ";
            getline(cin, s);

            if (s == "Y") {
                break;
            } else if (s == "n") {
                return;
            }
        }
    }

    if (p.insert(key, password) != 0) {
        cout << "Failed to add entry" << endl;
        return;
    }

    int ret = save_password_store(p);

    switch (ret) {
        case 0: {
            cout << "Added key " << key << " with password " << password << endl;
            break;
        }
        case -1: {
            cout << "Failed to save password store: Failed to open pass store file" << endl;
            break;
        }
        case -2: {
            cout << "Failed to save password store: Encryption error" << endl;
            break;

        }
        case -3: {
            cout << "Failed to save password store: File save error" << endl;
            break;
        }
        default: {
            cout << "Failed to save password store: Unknown error" << endl;
            break;
        }
    }
}

static void remove(Pass_Store &p)
{
    string key;
    cout << "Enter key to remove: ";
    getline(cin, key);

    while (true) {
        cout << "Are you sure you want to remove the key \"" << key << "\" ? Y/n ";
        string s;
        getline(cin, s);

        if (s == "Y") {
            break;
        } else if (s == "n") {
            return;
        }
    }

    if (p.remove(key) != 0) {
        cout << "Key not found" << endl;
        return;
    }

    cout << "Removed entry for key \"" << key << "\"" << endl;

    int ret = save_password_store(p);

    if (ret != 0) {
        cout << "Failed to save password store (" << to_string(ret) << ")" << endl;
    }
}

static void fetch(Pass_Store &p)
{
    string key;
    cout << "Enter key: ";
    getline(cin, key);

    if (!p.print_matches(key)) {
        cout << "Key not found" << endl;
    }
}

static void list(Pass_Store &p)
{
    p.print_matches("");
}

static void generate(void)
{
    string input;
    int size = 0;

    while (true) {
        cout << "Enter password length: ";
        getline(cin, input);

        try {
            size = stoi(input);
        } catch (const exception &) {
            cout << "Invalid input" << endl;
            continue;
        }

        if (size >= MIN_STORE_PASSWORD_SIZE && size <= MAX_STORE_PASSWORD_SIZE) {
            break;
        }

        cout << "Password must be between " << to_string(MIN_STORE_PASSWORD_SIZE) << " and " << to_string(MAX_STORE_PASSWORD_SIZE) << " characters in length" << endl;
    }

    string pass = random_password(size);

    if (pass.empty()) {
        cout << "Failed to generate password" << endl;
        return;
    }

    cout << pass << endl;
}

static void print_menu(void)
{
    cout << "Menu:" << endl;
    cout << "[1] Add entry" << endl;
    cout << "[2] Remove entry" << endl;
    cout << "[3] Fetch entry" << endl;
    cout << "[4] List all entries" << endl;
    cout << "[5] Generate password" << endl;
    cout << "[6] Change master password" << endl;
    cout << "[7] Print menu" << endl;
    cout << "[8] Exit" << endl;
}

static bool execute(const int option, Pass_Store &p)
{
    switch (option) {
        case 1: {
            add(p);
            break;
        }
        case 2: {
            remove(p);
            break;
        }
        case 3: {
            fetch(p);
            break;
        }
        case 4: {
            list(p);
            break;
        }
        case 5: {
            generate();
            break;
        }
        case 6: {
            new_password(p);
            break;
        }
        case 7: {
            clear_console();
            print_menu();
            break;
        }
        case 8: {  // exit program
            return false;
        }
        default: {
            cout << "Invalid command" << endl;
            print_menu();
            break;
        }
    }

    return true;
}

static int prompt(void)
{
    cout << "> ";
    string prompt;
    getline(cin, prompt);

    try {
        return stoi(prompt);
    }
    catch (const exception &) {
        return -1;
    }
}

static void menu_loop(Pass_Store &p)
{
    int option = -1;

    print_menu();

    while (true) {
        option = prompt();

        if (!execute(option, p)) {
            break;
        }
    }
}

/*
 * Initializes a new `Pass_Store` object and prompts user for password.
 *
 * Return 0 on success.
 * Return -1 if password prompt fails.
 * Return -2 if memory lock fails.
 * Return -3 if pass store file could not be opened.
 * Return -4 on invalid password.
 * Return -5 on decryption error.
 */
int new_pass_store(Pass_Store &p)
{
    unsigned char password[MAX_STORE_PASSWORD_SIZE + 1];

    if (crypto_memlock(password, sizeof(password)) != 0) {
        return -2;
    }

    if (first_time_run()) {
        cout << "Creating a new profile. ";

        if (init_new_password(password, MAX_STORE_PASSWORD_SIZE) != 0) {
            return -1;
        }
    } else {
        struct termios oflags;
        if (disable_terminal_echo(&oflags) != 0) {
            cout << "Warning: failed to disable terminal echo" << endl;
        }

        int pw_ret = prompt_password(password, MAX_STORE_PASSWORD_SIZE);
        enable_terminal_echo(&oflags);

        if (pw_ret != 0) {
            return -1;
        }
    }

    int ret = load_password_store(p, password, strlen((char *) password));

    if (crypto_memunlock(password, sizeof(password)) != 0) {
        cout << "Warning: crypto_memunlock() failed in new_pass_store()" << endl;
    }

    switch (ret) {
        case 0: {
            break;
        }
        case -1: {
            return -3;
        }
        case -2: {
            return -4;
        }
        case -3: {
            return -5;
        }
        case -4: {
            return -3;
        }
        default: {
            return -3;
        }
    }

    return 0;
}

static void print_version(const char *binary_name)
{
    cout << binary_name << " version "
         << BasedPass_VERSION_MAJOR << "."
         << BasedPass_VERSION_MINOR << "."
         << BasedPass_VERSION_PATCH << endl;
}

int main(int argc, char **argv)
{
    if (argc > 0) {
        print_version(argv[0]);
    }

    umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    if (crypto_init() != 0) {
        cout << "crypto_init() failed" << endl;
        return -1;
    }

    Pass_Store p;
    int ret = new_pass_store(p);

    switch (ret) {
        case 0: {
            break;
        }
        case -1: {
            return -1;
        }
        case -2: {
            cout << "crypto_memlock() failed in new_pass_store()" << endl;
            return -1;
        }
        case -3: {
            cout << "load_password_store() failed to open pass store file" << endl;
            return -1;
        }
        case -4: {
            cout << "Invalid password" << endl;
            return -1;
        }
        case -5: {
            cout << "Failed to decrypt pass store file" << endl;
            return -1;
        }
        default: {
            cout << "Unknown error" << endl;
            return -1;
        }
    }

    menu_loop(p);

    clear_console();

    return 0;
}
