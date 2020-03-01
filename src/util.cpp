/*  util.cpp
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

#include <iostream>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.hpp"

/*
 * Returns true if `s` contains `c`.
 */
bool string_contains(const std::string &s, const std::string &c)
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
#ifdef DEBUG
        std::cout << "Warning: failed to disable terminal echo" << std::endl;
#endif
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
std::vector<char> string_to_vec(const std::string &s)
{
    std::vector<char> result;

    for (char c: s) {
        result.push_back(c);
    }

    return result;
}

void clear_console(void)
{
    system("clear");
}

/*
 * Returns the current Unix time.
 */
time_t get_time(void)
{
    return time(NULL);
}

/*
 * Returns true if `t` has timed out relative to `timeout`.
 */
bool timed_out(time_t t, time_t timeout)
{
    return t + timeout <= get_time();
}

/*
 * Returns a vector containing the tokenized results of `s` split at
 * each instace of `token`.
 */
std::vector<std::string> string_split(const std::string &s, const std::string &token)
{
    std::vector<std::string> result;
    size_t last = 0;
    size_t next = 0;

    while ((next = s.find(token, last)) != std::string::npos) {
        std::string tok = s.substr(last, next-last);
        result.push_back(tok);
        last = next + 1;
    }

    return result;
}
