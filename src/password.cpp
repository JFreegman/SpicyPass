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

using namespace std;

#define NUM_GUARANTEED_CHARS (4)

#define PRINTABLE_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()=+_-{}[]:;'\",.<>/?\\|"

typedef enum {
    UPPERCASE,
    LOWERCASE,
    DIGIT,
    SYMBOL,
    NON_PRINTABLE,
} Char_Type;

/*
 * Returns the Char_Type of `c`.
 */
static Char_Type char_type(const char c)
{
    if (c >= 'A' && c <= 'Z') {
        return UPPERCASE;
    }

    if (c >= 'a' && c <= 'z') {
        return LOWERCASE;
    }

    if (c >= '0' && c <= '9') {
        return DIGIT;
    }

    if ((c >= '!' && c <= '/') || (c >= ':' && c <= '@') || (c >= '[' && c <= '`') || (c >= '{' && c <= '~')) {
        return SYMBOL;
    }

    return NON_PRINTABLE;
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
        case UPPERCASE: {
            if (! *have_upper) {
                *have_upper = true;
                return true;
            }
            break;
        }
        case LOWERCASE: {
            if (! *have_lower) {
                *have_lower = true;
                return true;
            }
            break;
        }
        case DIGIT: {
            if (! *have_digit) {
                *have_digit = true;
                return true;
            }
            break;
        }
        case SYMBOL: {
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

/* Returns a cryptographically secure randomly generated password.
 *
 * `size` must be greater than or equal to the number of guaranteed characters (4)
 * and less than or equal to the total number of ASCII printable characters.
 *
 * Password is guaranteed to meet minimum requirements as follows:
 * - At least one lower-case and upper-case letter
 * - At least one digit
 * - At least one symbol character
 * - No duplicate characters
 */
string random_password(unsigned int size)
{
    vector<char> result;
    vector<char> discarded;
    vector<char> char_vec = string_to_vec(string(PRINTABLE_CHARS));

#ifdef DEBUG
    assert(strlen(PRINTABLE_CHARS) == char_vec.size());
#endif

    if (size < NUM_GUARANTEED_CHARS || size > char_vec.size()) {
        cout << "random_password() error: invalid size value" << endl;
        return "";
    }

    bool have_lower = false;
    bool have_upper = false;
    bool have_digit = false;
    bool have_symbol = false;

    do {
        auto vec_size = char_vec.size();

        if (vec_size == 0) {
            char_vec = discarded;
#ifdef DEBUG
            assert(char_vec.size() != 0);
#endif
            continue;
        }

        auto index = crypto_random_number(vec_size);
        auto c = char_vec.at(index);
        char_vec.erase(char_vec.begin() + index);

        if (good_char(c, &have_lower, &have_upper, &have_digit, &have_symbol)) {
            result.push_back(c);
        } else {
            discarded.push_back(c);
        }
    } while (result.size() < size);

    shuffle_vec(result);

    return vec_to_string(result);
}
