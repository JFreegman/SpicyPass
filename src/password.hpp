/*  password.hpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
 */

#ifndef PASSWORD_H
#define PASSWORD_H

#include <string>

/* The min/max number of characters a randomly generated password can have respectively. */
#define NUM_RAND_PASS_MAX_CHARS (256)
#define NUM_RAND_PASS_MIN_CHARS (10)

/*
 * Returns a cryptographically secure randomly generated password.
 *
 * `size` must be greater than or equal to the number of guaranteed characters (4)
 * and less than or equal to the total number of ASCII printable characters.
 *
 * Password is guaranteed to meet minimum requirements as follows:
 * - At least one lower-case and upper-case letter
 * - At least one digit
 * - At least one symbol
 */
std::string random_password(unsigned int size);

#endif // PASSWORD_H
