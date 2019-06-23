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

#include <string>
#include "load.hpp"
#include "password.hpp"

using namespace std;

#define MAX_PASSWORD_SIZE 32
#define MIN_PASSWORD_SIZE 8

#define MAX_KEY_SIZE 32

static void add(unordered_map<string, string> &pass_store)
{
    string key, password;

    cout << "Enter key: ";
    getline(cin, key);

    if (key.length() > MAX_KEY_SIZE) {
        cout << "Key is too long" << endl;
        return;
    }

    cout << "Enter password (leave empty to randomly generate): ";
    getline(cin, password);

    if (password.length() > MAX_PASSWORD_SIZE) {
        cout << "Password must be between " << to_string(MIN_PASSWORD_SIZE) << " and " << to_string(MAX_PASSWORD_SIZE) << " bytes in length" << endl;
        return;
    }

    if (password.empty()) {
        password = random_password(16);
    }

    if (pass_store.find(key) != pass_store.end()) {
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

    pass_store.insert_or_assign(key, password);
    int ret = save_password_store(pass_store);

    if (ret != 0) {
        cout << "Failed to save password store (" << to_string(ret) << ")" << endl;
    } else {
        cout << "Added key " << key << " with password " << password << endl;
    }
}

static void remove(unordered_map<string, string> &pass_store)
{
    string key;
    cout << "Enter key: ";
    getline(cin, key);

    if (pass_store.find(key) == pass_store.end()) {
        cout << "Key not found" << endl;
        return;
    }

    pass_store.erase(key);
    int ret = save_password_store(pass_store);

    if (ret != 0) {
        cout << "Failed to save password store (" << to_string(ret) << ")" << endl;
    } else {
        cout << "Removed entry for key \"" << key << "\"" << endl;
    }
}

static void fetch(unordered_map<string, string> &pass_store)
{
    string key;
    cout << "Enter key: ";
    getline(cin, key);

    auto result = pass_store.find(key);

    if (result == pass_store.end()) {
        cout << "Key not found" << endl;
        return;
    }

    cout << result->second << endl;
}

static void list(unordered_map<string, string> &pass_store)
{
    for (auto &p: pass_store) {
        cout << p.first << ": " << p.second << endl;
    }
}

static void generate(void)
{
    string input;
    int size = 0;

    while (size < MIN_PASSWORD_SIZE || size > MAX_PASSWORD_SIZE) {
        cout << "Enter password length: ";
        getline(cin, input);

        try {
            size = stoi(input);
        }
        catch (const invalid_argument &) {
            cout << "Invalid input" << endl;
            continue;
        }

        if (size < MIN_PASSWORD_SIZE || size > MAX_PASSWORD_SIZE) {
            cout << "Password must be between " << to_string(MIN_PASSWORD_SIZE) << " and " << to_string(MAX_PASSWORD_SIZE) << " characters in length" << endl;
        }
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

static bool execute(const int option, unordered_map<string, string> &pass_store)
{
    switch (option) {
        case 1: {
            add(pass_store);
            break;
        }
        case 2: {
            remove(pass_store);
            break;
        }
        case 3: {
            fetch(pass_store);
            break;
        }
        case 4: {
            list(pass_store);
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
    cout << ">> ";

    string prompt;
    getline(cin, prompt);

    try {
        return stoi(prompt);
    }
    catch (const invalid_argument &) {
        return -1;
    }
}

static void menu_loop(unordered_map<string, string> &pass_store)
{
    int option = -1;

    print_menu();

    while (true) {
        option = prompt();

        if (!execute(option, pass_store)) {
            cout << "Goodbye :)" << endl;
            break;
        }
    }
}

int main(void)
{
    unordered_map<string, string> pass_store;

    int ret = load_password_store(pass_store);

    if (ret != 0) {
        cout << "Failed to load password store (" + to_string(ret) + ")" << endl;
        return -1;
    }

    menu_loop(pass_store);

    return 0;
}