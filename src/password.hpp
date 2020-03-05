/*  password.hpp
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

#ifndef PASSWORD
#define PASSWORD

#include <string>

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
std::string random_password(unsigned int size);

#endif // PASSWORD
