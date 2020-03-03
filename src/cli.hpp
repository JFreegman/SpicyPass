/*  cli.hpp
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

#ifndef CLI
#define CLI

void run_cli_interface(Pass_Store &p);

/*
 * Initializes a new `Pass_Store` object and prompts user for password.
 *
 * Return 0 on success.
 * Return -1 if password prompt fails.
 * Return -2 if memory lock fails.
 * Return -3 if pass store file could not be opened.
 * Return -4 on invalid password.
 * Return -5 on decryption error.
 */
int cli_new_pass_store(Pass_Store &p);

#endif // CLI