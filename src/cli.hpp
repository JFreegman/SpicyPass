/*  cli.hpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
 */

#ifndef CLI_H
#define CLI_H

#include "spicy.hpp"

void run_cli(Pass_Store &p);

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

#endif // CLI_H
