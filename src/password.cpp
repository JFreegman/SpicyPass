/*  password.cpp
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

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <time.h>

#include "load.hpp"

using namespace std;

/*
 * Adds all characters from the `chars` string to `vec` and shuffles the resulting vector.
 */
static void init_char_vector(vector<char> &vec)
{
    const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()=+_-{}[]:;'\",.<>/?\\|";

    for (char c: chars) {
        vec.push_back(c);
    }

    random_shuffle(vec.begin(), vec.end());
}

/*
 * Removes the first character in `in_vec` between the range `start` and `end` inclusive
 * and puts it in `out_vec`.
 */
static void get_char_range(vector<char> &in_vec, vector<char> &out_vec, int start, int end)
{
    for (unsigned int i = 0; i < in_vec.size(); ++i) {
        char c = in_vec[i];

        if (c >= start && c <= end) {
            in_vec.erase(in_vec.begin() + i);
            out_vec.push_back(c);
            return;
        }
    }
}

/*
 * Removes the first non-alphanumeric character in `in_vec` and puts it in `out_vec`.
 */
static void get_char_punctuation(vector<char> &in_vec, vector<char> &out_vec)
{
    for (unsigned int i = 0; i < in_vec.size(); ++i) {
        char c = in_vec[i];

        if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9')) {
            in_vec.erase(in_vec.begin() + i);
            out_vec.push_back(c);
            return;
        }
    }
}

/* Returns a randomly generated password.
 *
 * Password is guaranteed to meet minimum requirements as follows:
 * - At least one lower-case and upper-case letter
 * - At least one digit
 * - At least one punctuation character
 * - No duplicate characters
 */
string random_password(int size)
{
    if (size <= 4) {
        cout << "random_password() error: invalid size value" << endl;
        return "";
    }

    srand(time(NULL));

    vector<char> char_vec;
    vector<char> res_vec;
    init_char_vector(char_vec);

    get_char_range(char_vec, res_vec, 'A', 'Z');
    get_char_range(char_vec, res_vec, 'a', 'z');
    get_char_range(char_vec, res_vec, '0', '9');
    get_char_punctuation(char_vec, res_vec);

    for (int i = 0; i < (size - 4); ++i) {
        char c = char_vec[i];
        char_vec.erase(char_vec.begin() + i);
        res_vec.push_back(c);
    }

    // One last shuffle so the guaranteed chars aren't all at the front
    random_shuffle(res_vec.begin(), res_vec.end());

    string pass = "";

    for (char c: res_vec) {
        pass += c;
    }

    return pass;
}
