/*  util.cpp
 *
 *
 *  Copyright (C) 2020-2024 Jfreegman <Jfreegman@gmail.com>
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

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#endif // _WIN32

#include <iostream>

#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "util.hpp"

bool string_contains(const std::string &s, const std::string &c)
{
    return s.find(c) != std::string::npos;
}

bool file_is_empty(std::ifstream &fp)
{
    return fp.peek() == std::ifstream::traits_type::eof();
}

off_t file_size(const char *path)
{
    struct stat st;

    if (stat(path, &st) == -1) {
        return 0;
    }

    return st.st_size;
}

void remove_file(const std::string &path)
{
    if (remove(path.c_str()) != 0) {
        std::cerr << "Warning: remove() failed on path: " << path << std::endl;
    }
}

void terminal_echo(bool enable)
{
#if defined(_WIN32)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;

    int ret = GetConsoleMode(hStdin, &mode);

    if (!ret) {
        std::cerr << "Warning: GetConsoleMode() returned error: " << std::to_string(ret) << std::endl;
        return;
    }

    if (!enable) {
        mode &= (~ENABLE_ECHO_INPUT);
    } else {
        mode |= ENABLE_ECHO_INPUT;
    }

    ret = SetConsoleMode(hStdin, mode);

    if (!ret) {
        std::cerr << "Warning: SetConsoleMode() returned error: " << std::to_string(ret) << std::endl;
        return;
    }

#else
    struct termios tty;

    if (tcgetattr(STDIN_FILENO, &tty) != 0) {
        std::cerr << "Warning: tcgetattr() returned error. errno: " << std::to_string(errno) << std::endl;
        return;
    }

    if (!enable) {
        tty.c_lflag &= (~ECHO);
    } else {
        tty.c_lflag |= ECHO;
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &tty) != 0) {
        std::cerr << "Warning: tcsetattr() returned error. errno: " << std::to_string(errno) << std::endl;
        return;
    }

#endif // _WIN32
}

void clear_console(void)
{
    printf("\033[2J\033[1;1H");
}

time_t get_time(void)
{
    return time(NULL);
}

bool timed_out(time_t t, time_t timeout)
{
    return t + timeout <= get_time();
}

std::vector<std::string> string_split(const std::string &s, const std::string &token)
{
    std::vector<std::string> result;
    size_t last = 0;
    size_t next = 0;

    while ((next = s.find(token, last)) != std::string::npos) {
        std::string tok = s.substr(last, next - last);
        result.push_back(tok);
        last = next + 1;
    }

    return result;
}

std::string vec_to_string(const std::vector<char> &vec)
{
    std::string s;

    for (const char c : vec) {
        s += c;
    }

    return s;
}

std::vector<char> string_to_vec(const std::string &s)
{
    std::vector<char> result;

    for (const char c : s) {
        result.push_back(c);
    }

    return result;
}

bool string_printable(const std::string &s)
{
    for (const char c : s) {
        if (!isprint(c)) {
            return false;
        }
    }

    return true;
}
