/*  password.cpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
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

    const Char_Type type = char_type(c);

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
    const size_t vec_size = vec.size();

    if (vec_size == 0) {
        return;
    }

    for (size_t i = vec_size - 1; i > 0; --i) {
        const auto index = crypto_random_number(i + 1);
        swap(vec[i], vec[index]);
    }
}

bool password_invalid(const vector<char> &pass)
{
    if (pass.size() == 0) {
        return true;
    }

    return pass[0] == '\0';
}

vector<char> random_password(unsigned int size)
{
    vector<char> result;
    vector<char> char_vec = string_to_vec(string(PRINTABLE_CHARS));
    const auto char_vec_size = char_vec.size();

    if (size < NUM_RAND_PASS_MIN_CHARS || size > NUM_RAND_PASS_MAX_CHARS) {
        cerr << "random_password() error: invalid size value" << endl;
        result.push_back('\0');
        return result;
    }

    bool have_lower = false;
    bool have_upper = false;
    bool have_digit = false;
    bool have_symbol = false;
    char last_char = 0;

    do {
        const auto index = crypto_random_number(char_vec_size);
        const auto c = char_vec.at(index);

        if (c == last_char) {
            continue;
        }

        if (good_char(c, &have_lower, &have_upper, &have_digit, &have_symbol)) {
            result.push_back(c);
            last_char = c;
        }
    } while (result.size() < size);

    shuffle_vec(result);

    result.push_back('\0');

    return result;
}
