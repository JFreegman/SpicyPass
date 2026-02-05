/*  util.cpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
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

void write_field(std::ofstream &fp, const std::string &s)
{
    fp << s.size() << ":" << s;
}

static bool get_field_length(std::ifstream &fp, std::string &len_str)
{
    char c;

    while (fp.get(c)) {
        if (c == ':') {  // all chars prior to colon are the length of the field
            break;
        }

        if (c == '\n' || c == '\r') {
            continue;
        }

        if (!std::isdigit(c)) {
            std::cerr << "Not a digit: " << c << std::endl;
            return false;
        }

        len_str.push_back(c);
    }

    return true;
}

static bool read_field(std::ifstream &fp, std::string &field)
{
    std::string len_str = "";

    if (!get_field_length(fp, len_str)) {
        return false;
    }

    if (len_str.length() == 0 || len_str == "0") { // empty field
        return true;
    }

    size_t field_len = 0;

    try {
        field_len = std::stoul(len_str);
    } catch (std::exception &e) {
        std::cerr << "Failed to convert string to integer: " << len_str << std::endl;
        return false;
    }

    field.resize(field_len);

    if (field_len > field.max_size()) {
        return false;
    }

    fp.read(field.data(), field_len);

    if (!fp) {
        std::cerr << "read_field failed on field: " << field << " (len: " << field_len << ")" << std::endl;
        return false;
    }

    return true;
}

bool read_entry_fields(std::ifstream &fp, std::string &key, std::string &pass, std::string &note)
{
    if (!fp) {
        return false;
    }

    return read_field(fp, key)
           && read_field(fp, pass)
           && read_field(fp, note);
}
