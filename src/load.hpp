/*  load.hpp
 *
 *
 *  Copyright (C) 2019 Jfreegman <Jfreegman@gmail.com>
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

#ifndef LOAD
#define LOAD

#include <unistd.h>
#include <pwd.h>

#include "based.hpp"

/*
 * Attempts to validate password, decrypt password store, and load it to memory.
 *
 * Return 0 on success.
 * Return -1 on file related error.
 * Return -2 if password is invalid.
 * Return -3 on crypto related error.
 * Return -4 if memory lock fails.
 * Return -5 if magic number is wrong.
 */
int load_password_store(Pass_Store &p, const unsigned char *password, size_t length);

/*
 * Saves encrypted contents of pass store to disk.
 *
 * Return 0 on success.
 * Return -1 if path is invalid.
 * Return -2 if file encryption fails.
 */
int save_password_store(Pass_Store &p);

/*
 * Return 1 if pass_store file does not exist or is empty.
 * Return 0 if pass_store file exists.
 * Return -1 if invalid path.
 * Return -2 if file cannot be opened.
 */
int first_time_run(void);

/*
 * Puts hash of `password` at the beginning of based store file.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int init_pass_hash(const unsigned char *password, size_t length);

#endif