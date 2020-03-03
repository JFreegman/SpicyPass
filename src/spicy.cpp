/*  spicy.cpp
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

#include <SpicyPassConfig.h>

#include <thread>
#include <chrono>

#include <sys/stat.h>

#include "password.hpp"
#include "spicy.hpp"
#include "crypto.hpp"
#include "cli.hpp"

using namespace std;


static void print_version(const char *binary_name)
{
    cout << binary_name << " version "
         << SpicyPass_VERSION_MAJOR << "."
         << SpicyPass_VERSION_MINOR << "."
         << SpicyPass_VERSION_PATCH << endl;
}

void store_lock_loop(Pass_Store &p)
{
    while(true) {
        p.poll_idle();
        this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void set_file_permissions(void)
{
    umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
}

int main(int argc, char **argv)
{
    if (argc > 0) {
        print_version(argv[0]);
    }

    set_file_permissions();

    if (crypto_init() != 0) {
        cout << "crypto_init() failed" << endl;
        return -1;
    }

    Pass_Store p;
    int ret = cli_new_pass_store(p);

    switch (ret) {
        case 0: {
            break;
        }
        case -1: {
            return -1;
        }
        case -2: {
            cout << "crypto_memlock() failed in new_pass_store()" << endl;
            return -1;
        }
        case -3: {
            cout << "load_password_store() failed to open pass store file" << endl;
            return -1;
        }
        case -4: {
            cout << "Invalid password" << endl;
            return -1;
        }
        case -5: {
            cout << "Failed to decrypt pass store file" << endl;
            return -1;
        }
        default: {
            cout << "Unknown error" << endl;
            return -1;
        }
    }

    thread t(store_lock_loop, ref(p));
    t.detach();

    run_cli_interface(p);

    return 0;
}
