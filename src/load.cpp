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

#include <unistd.h>
#include <pwd.h>
#include <fstream>

#include "load.hpp"

using namespace std;

#define DEFAULT_FILENAME ".based_store"

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

int load_password_store(unordered_map<string, string> &pass_store)
{
    const string path = get_store_path();

    if (path == "") {
        return -1;
    }

    ifstream fp;

    try {
        fp.open(path);
    }
    catch (fstream::failure) {
        return -2;
    }

    string key, pass;

    while (fp >> key >> pass) {
        pass_store.insert({key, pass});
    }

    fp.close();

    return 0;
}

int save_password_store(unordered_map<string, string> &pass_store)
{
    const string path = get_store_path();

    if (path == "") {
        return -1;
    }

    ofstream fp;

    try {
        fp.open(path);
    }
    catch (ofstream::failure) {
        return -2;
    }

    for (auto &p: pass_store) {
        string entry = p.first + ' ' + p.second + '\n';
        fp << entry;
    }

    fp.close();

    return 0;
}