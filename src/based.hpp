/*  based.hpp
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

#ifndef BASED
#define BASED

#include <iostream>
#include <string>
#include <fstream>
#include <map>

#include "load.hpp"

#define DELIMITER ":"

using namespace std;

class Pass_Store {
    map<string, string> store;

public:
    void insert(string key, string value) {
        store.insert_or_assign(key, value);
    }

    void remove(string key) {
        store.erase(key);
    }

    bool key_exists(string key) {
        return store.find(key) != store.end();
    }

    bool print_matches(string key) {
        bool match = false;

        for (auto &item: store) {
            if (key.compare(0, key.length(), item.first, 0, key.length()) == 0) {
                cout << item.first << ": " << item.second << endl;
                match = true;
            }
        }

        return match;
    }

    void load(ifstream &fp) {
        string line, key, pass;

        while (getline(fp, line)) {
            unsigned int d = line.find(DELIMITER);

            if (d == string::npos) {
                continue;
            }

            key = line.substr(0, d);
            pass = line.substr(d + 1, line.length());
            insert(key, pass);
        }
    }

    void save(ofstream &fp) {
        for (auto &item: store) {
            string entry = item.first + DELIMITER + item.second + '\n';
            fp << entry;
        }
    }
};

#endif