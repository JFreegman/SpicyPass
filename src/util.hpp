/*  util.hpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
 */

#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <fstream>
#include <vector>

#include <string.h>

#define UNUSED_VAR(x) ((void) x)

/*
 * Returns true if `s` contains `c`.
 */
bool string_contains(const std::string &s, const std::string &c);

/*
 * Returns true if file pointed to by `fp` is empty.
 */
bool file_is_empty(std::ifstream &fp);

/* Returns the size of the file pointed to by `path`. */
off_t file_size(const char *path);

/*
 * Attempts to remove file located at `path`. This is just a wrapper for the stdio.h remove()
 * function. We use this for when we only want a stderr warning on failure.
 */
void remove_file(const std::string &path);

/*
 * Disables or enables terminal echo depending on `enable` boolean.
 */
void terminal_echo(bool enable);


void clear_console(void);

/*
 * Returns the local time.
 */
time_t get_time(void);

/*
 * Returns true if `t` has timed out relative to `timeout`.
 */
bool timed_out(time_t t, time_t timeout);

/*
 * Returns a vector containing the tokenized results of `s` split at
 * each instace of `token`.
 */
std::vector<std::string> string_split(const std::string &s, const std::string &token);

/*
 * Returns a string containing the charaters in `vec`.
 */
std::string vec_to_string(const std::vector<char> &vec);

/*
 * Returns a vector containing the characters in `s`.
 */
std::vector<char> string_to_vec(const std::string &s);

/*
 * Return true if all characters in `s` are printable (ASCII).
 */
bool string_printable(const std::string &s);

#endif // UTIL_H
