/*  password.cpp
 *
 *
 *  Copyright (C) 2020 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass.
 *
 *  SpicyPass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SpicyPass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SpicyPass.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <string>
#include <assert.h>

#include "crypto.hpp"
#include "util.hpp"
#include "password.hpp"

using namespace std;

#define PRINTABLE_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()=+_-{}[]:;'\",.<>/?\\|"

typedef enum {
    CHAR_UPPERCASE = 0,
    CHAR_LOWERCASE,
    CHAR_DIGIT,
    CHAR_SYMBOL,
    CHAR_NON_PRINTABLE,
} Char_Type;

/*
 * Returns the Char_Type of `c`.
 */
static Char_Type char_type(const char c)
{
    if (c >= 'A' && c <= 'Z') {
        return CHAR_UPPERCASE;
    }

    if (c >= 'a' && c <= 'z') {
        return CHAR_LOWERCASE;
    }

    if (c >= '0' && c <= '9') {
        return CHAR_DIGIT;
    }

    if ((c >= '!' && c <= '/') || (c >= ':' && c <= '@') || (c >= '[' && c <= '`') || (c >= '{' && c <= '~')) {
        return CHAR_SYMBOL;
    }

    return CHAR_NON_PRINTABLE;
}

/*
 * Returns true if `c` is a char type that has not been seen yet, or if
 * all char types have been seen.
 */
static bool good_char(const char c, bool *have_lower, bool *have_upper,
                      bool *have_digit, bool *have_symbol)
{
    if (*have_lower && *have_upper && *have_digit && *have_symbol) {
        return true;
    }

    Char_Type type = char_type(c);

    switch (type) {
        case CHAR_UPPERCASE: {
            if (! *have_upper) {
                *have_upper = true;
                return true;
            }

            break;
        }

        case CHAR_LOWERCASE: {
            if (! *have_lower) {
                *have_lower = true;
                return true;
            }

            break;
        }

        case CHAR_DIGIT: {
            if (! *have_digit) {
                *have_digit = true;
                return true;
            }

            break;
        }

        case CHAR_SYMBOL: {
            if (! *have_symbol) {
                *have_symbol = true;
                return true;
            }

            break;
        }

        default: {
            break;
        }
    }

    return false;
}

/*
 * Shuffles items in `vec`.
 */
static void shuffle_vec(vector<char> &vec)
{
    auto vec_size = vec.size();

    for (size_t i = 0; i < vec_size; ++i) {
        auto index = crypto_random_number(vec_size);
        auto a = vec.at(i);
        vec.at(i) = vec.at(index);
        vec.at(index) = a;
    }
}

string random_password(unsigned int size)
{
    vector<char> result;
    vector<char> char_vec = string_to_vec(string(PRINTABLE_CHARS));
    auto char_vec_size = char_vec.size();

    if (size < NUM_RAND_PASS_MIN_CHARS || size > NUM_RAND_PASS_MAX_CHARS) {
        cerr << "random_password() error: invalid size value" << endl;
        return "";
    }

    bool have_lower = false;
    bool have_upper = false;
    bool have_digit = false;
    bool have_symbol = false;
    char last_char = 0;

    do {
        auto index = crypto_random_number(char_vec_size);
        auto c = char_vec.at(index);

        if (c == last_char) {
            continue;
        }

        if (good_char(c, &have_lower, &have_upper, &have_digit, &have_symbol)) {
            result.push_back(c);
            last_char = c;
        }
    } while (result.size() < size);

    shuffle_vec(result);

    return vec_to_string(result);
}
