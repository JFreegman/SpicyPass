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

#include "load.hpp"
#include "password.hpp"
#include "based.hpp"
#include "util.hpp"

using namespace std;

#define MAX_PASSWORD_SIZE 32
#define MIN_PASSWORD_SIZE 8

#define MAX_KEY_SIZE 32

static void add(Pass_Store &p)
{
    string key, password;

    cout << "Enter key: ";
    getline(cin, key);

    if (key.length() > MAX_KEY_SIZE) {
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


int init_pass_store(Pass_Store &p)
{
    int ret = load_password_store(p);

    if (ret != 0) {
        cout << "Failed to load password store (" + to_string(ret) + ")" << endl;
        return -1;
    }

    return 0;
}

int main(void)
{
    umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    if (init_rand() != 0) {
        cout << "init_rand() failed. Exiting." << endl;
        return -1;
    }

    Pass_Store p;
    int ret = init_pass_store(p);

    if (ret != 0) {
        cout << "Failed to init pass store object" << endl;
        return -1;
    }

    menu_loop(p);

    return 0;
}