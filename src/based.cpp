/*  based.cpp
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

#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>

#include "load.hpp"
#include "password.hpp"
#include "based.hpp"
#include "util.hpp"
#include "crypto.hpp"

using namespace std;

#define MAX_PASSWORD_SIZE 32
#define MIN_PASSWORD_SIZE 8
#define MAX_ENTRY_KEY_SIZE 32

static void add(Pass_Store &p)
{
    string key, password;

    cout << "Enter key: ";
    getline(cin, key);

    if (key.length() > MAX_ENTRY_KEY_SIZE) {
        cout << "Key is too long" << endl;
        return;
    }

    if (string_contains(key, DELIMITER)) {
        cout << "Key may not contain the \"" << DELIMITER << "\" character" << endl;
        return;
    }

    cout << "Enter password: ";
    getline(cin, password);

    if (password.length() > MAX_PASSWORD_SIZE) {
        cout << "Password length must not exceed " << to_string(MAX_PASSWORD_SIZE) << " characters" << endl;
        return;
    }

    if (password.empty()) {
        password = random_password(16);
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

    p.insert(key, password);
    int ret = save_password_store(p);

    if (ret != 0) {
        cout << "Failed to save password store (" << to_string(ret) << ")" << endl;
    } else {
        cout << "Added key " << key << " with password " << password << endl;
    }
}

static void remove(Pass_Store &p)
{
    string key;
    cout << "Enter key: ";
    getline(cin, key);

    if (!p.key_exists(key)) {
        cout << "Key not found" << endl;
        return;
    }

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

    p.remove(key);
    int ret = save_password_store(p);

    if (ret != 0) {
        cout << "Failed to save password store (" << to_string(ret) << ")" << endl;
    } else {
        cout << "Removed entry for key \"" << key << "\"" << endl;
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
        }
        catch (const exception &) {
            cout << "Invalid input" << endl;
            continue;
        }

        if (size >= MIN_PASSWORD_SIZE && size <= MAX_PASSWORD_SIZE) {
            break;
        }

        cout << "Password must be between " << to_string(MIN_PASSWORD_SIZE) << " and " << to_string(MAX_PASSWORD_SIZE) << " characters in length" << endl;
    }

    string pass = random_password(size);
    cout << pass << endl;
}

static void print_menu(void)
{
    cout << "Menu:" << endl;
    cout << "[1] Add" << endl;
    cout << "[2] Remove" << endl;
    cout << "[3] Fetch" << endl;
    cout << "[4] List" << endl;
    cout << "[5] Generate" << endl;
    cout << "[6] Menu" << endl;
    cout << "[7] Exit" << endl;
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
            print_menu();
            break;
        }
        case 7: {  // exit program
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
            cout << "Goodbye :)" << endl;
            break;
        }
    }
}

/* Promps password and puts it in `password` array.
 *
 * Return 0 on success.
 * Return -1 input is invalid.
 */
static int prompt_password(char *password, size_t max_length)
{
    /* disable terminal echo */
    struct termios oflags, nflags;
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        cout << "Warning: tcsetattr() failed to disable terminal echo" << endl;
    }

    cout << "Enter password: ";

    char pass_buf[max_length + 1];
    const char *input = fgets(pass_buf, sizeof(pass_buf), stdin);

    if (input == NULL) {
        cout << "Invalid input." << endl;
        return -1;
    }

    size_t pass_length = strlen(pass_buf);

    /* re-enable terminal echo */
    tcsetattr(fileno(stdin), TCSANOW, &oflags);

    if (pass_length > max_length) {
        return -1;
    }

    memcpy(password, pass_buf, pass_length);
    password[pass_length] = 0;

    crypto_memwipe(pass_buf, sizeof(pass_buf));

    return 0;
}

static void new_password_prompt(char *password, size_t max_length)
{
    cout << "Creating a new profile. ";

    /* disable terminal echo */
    struct termios oflags, nflags;
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        cout << "Warning: tcsetattr() failed to disable terminal echo." << endl;
    }

    while (true) {
        cout << "Enter password: ";

        char pass1[max_length + 1];
        char pass2[max_length + 1];

        const char *input1 = fgets(pass1, sizeof(pass1), stdin);

        if (input1 == NULL) {
            cout << "Invalid input." << endl;
            continue;
        }

        size_t pass_length = strlen(pass1);

        if (pass_length < MIN_PASSWORD_SIZE || pass_length > max_length) {
            cout << "Password must be between " << MIN_PASSWORD_SIZE  << " and " << max_length << " characters long." << endl;
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

        /* re-enable terminal echo */
        tcsetattr(fileno(stdin), TCSANOW, &oflags);

        memcpy(password, pass1, pass_length);
        password[pass_length] = 0;

        crypto_memwipe(pass1, pass_length);
        crypto_memwipe(pass2, pass_length);

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
static int init_new_password(char *password, size_t max_length)
{
    new_password_prompt(password, max_length);

    if (init_pass_hash(password, strlen(password)) != 0) {
        cout << "init_pass_hash() failed." << endl;
        return -1;
    }

    return 0;
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
    char password[MAX_PASSWORD_SIZE + 1];

    if (first_time_run()) {
        if (init_new_password(password, MAX_PASSWORD_SIZE) != 0) {
            return -1;
        }
    } else if (prompt_password(password, MAX_PASSWORD_SIZE) != 0) {
        return -1;
    }

    if (crypto_memlock(password, sizeof(password)) != 0) {
        return -2;
    }

    int ret = load_password_store(p, password, strlen(password));

    if (crypto_memunlock(password, sizeof(password)) != 0) {
        cout << "Warning: crypto_memunlock() failed in new_pass_store()" << endl;
    }

    switch (ret) {
        case -1: {
            return -3;
        }
        case -2: {
            return -4;
        }
        case -3: {
            return -5;
        }
    }

    return 0;
}

int main(void)
{
    umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    if (init_rand() != 0) {
        cout << "init_rand() failed." << endl;
        return -1;
    }

    if (crypto_init() != 0) {
        cout << "init_crypto() failed." << endl;
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

    p.kill();

    return 0;
}