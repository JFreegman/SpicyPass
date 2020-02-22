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

#include <string>
#include <vector>

#include "crypto.hpp"

using namespace std;

/*
 * Adds all characters from the `chars` string to `vec`.
 */
static void init_char_vector(vector<char> &vec)
{
    const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()=+_-{}[]:;'\",.<>/?\\|";

    for (char c: chars) {
        vec.push_back(c);
    }
}

/*
 * Returns true if `c` should be added to `pass`.
 */
static bool good_char(const char c, bool *have_lower, bool *have_upper,
                      bool *have_digit, bool *have_punct)
{
    if (*have_lower && *have_upper && *have_digit && *have_punct) {
        return true;
    }

    if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9')) {
        if (! *have_punct) {
            *have_punct = true;
            return true;
        }
    } else if (c >= '0' && c <= '9') {
        if (! *have_digit) {
            *have_digit = true;
            return true;
        }
    } else if (c >= 'A' && c <= 'Z') {
        if (! *have_upper) {
            *have_upper = true;
            return true;
        }
    } else if (c >= 'a' && c <= 'z') {
        if (! *have_lower) {
            *have_lower = true;
            return true;
        }
    }

    return false;
}

/* Returns a randomly generated password.
 *
 * Password is guaranteed to meet minimum requirements as follows:
 * - At least one lower-case and upper-case letter
 * - At least one digit
 * - At least one punctuation character
 * - No duplicate characters
 */
string random_password(unsigned int size)
{
    string pass = "";

    vector<char> char_vec;
    vector<char> discarded;
    init_char_vector(char_vec);

    if (size <= 4 || size > char_vec.size()) {
        cout << "random_password() error: invalid size value" << endl;
        return "";
    }

    bool have_lower = false;
    bool have_upper = false;
    bool have_digit = false;
    bool have_punct = false;

    do {
        auto vec_size = char_vec.size();

        if (vec_size == 0) {
            char_vec = discarded;
            continue;
        }

        auto index = crypto_random_number(vec_size);
        auto c = char_vec[index];
        char_vec.erase(char_vec.begin() + index);

        if (good_char(c, &have_lower, &have_upper, &have_digit, &have_punct)) {
            pass += c;
        } else {
            discarded.push_back(c);
        }
    } while (pass.length() < size);

    return pass;
}
