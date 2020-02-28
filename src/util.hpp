/*  util.hpp
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

#ifndef UTIL
#define UTIL

#include <string>
#include <fstream>
#include <vector>

#include <string.h>
#include <termios.h>


/*
 * Returns true if `s` contains `c`.
 */
bool string_contains(std::string s, std::string c);

/*
 * Returns true if file pointed to by `fp` is empty.
 */
bool file_is_empty(std::ifstream &fp);

/* Returns the size of the file pointed to by `path`. */
off_t file_size(const char *path);

/*
 * These functions disable and enable terminal echo respectively.
 */
int disable_terminal_echo(struct termios *oflags);
void enable_terminal_echo(struct termios *oflags);

/*
 * Returns a string containing the charaters in `vec`.
 */
std::string vec_to_string(const std::vector<char> &vec);

/*
 * Returns a vector containing the characters in `s`.
 */
std::vector<char> string_to_vec(std::string s);

void clear_console(void);

/*
 * Returns the current Unix time.
 */
time_t get_time(void);

/*
 * Returns true if `t` has timed out relative to `timeout`.
 */
bool timed_out(time_t t, time_t timeout);

#endif // UTIL
