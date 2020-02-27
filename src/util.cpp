/*  util.cpp
 *
 *
 *  Copyright (C) 2020 Jfreegman <Jfreegman@gmail.com>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.hpp"

/*
 * Returns true if `s` contains `c`.
 */
bool string_contains(std::string s, std::string c)
{
    return s.find(c) != std::string::npos;
}

/*
 * Returns true if file pointed to by `fp` is empty.
 */
bool file_is_empty(std::ifstream &fp)
{
    return fp.peek() == std::ifstream::traits_type::eof();
}

/* Returns the size of the file pointed to by `path`. */
off_t file_size(const char *path)
{
    struct stat st;

    if (stat(path, &st) == -1) {
        return 0;
    }

    return st.st_size;
}

int disable_terminal_echo(struct termios *oflags)
{
    struct termios nflags;
    tcgetattr(fileno(stdin), oflags);
    nflags = *oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
        return -1;
    }

    return 0;
}

void enable_terminal_echo(struct termios *oflags)
{
    tcsetattr(fileno(stdin), TCSANOW, oflags);
}

/*
 * Returns a string containing the charaters in `vec`.
 */
std::string vec_to_string(const std::vector<char> &vec)
{
    std::string s = "";

    for (char c: vec) {
        s += c;
    }

    return s;
}

/*
 * Returns a vector containing the characters in `s`.
 */
std::vector<char> string_to_vec(std::string s)
{
    std::vector<char> result;

    for (char c: s) {
        result.push_back(c);
    }

    return result;
}
