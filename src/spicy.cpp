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

#include <thread>
#include <chrono>

#include <sys/stat.h>

#include "password.hpp"
#include "spicy.hpp"
#include "crypto.hpp"
#include "cli.hpp"
#include "gui.hpp"

using namespace std;

static void print_usage_exit(void)
{
    cout << "Usage: spicypass [--gui | --cli]" << endl;
    exit(-1);
}

static void print_version(const char *binary_name)
{
#ifndef _WIN32
    cout << binary_name << " version "
         << SpicyPass_VERSION_MAJOR << "."
         << SpicyPass_VERSION_MINOR << "."
         << SpicyPass_VERSION_PATCH << endl;
#endif // _WIN32
}

void store_lock_loop(Pass_Store &p)
{
    while(true) {
        p.poll_idle();
        this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

/*
 * Return true if the --gui option is set and we have gui support.
 */
bool gui_enabled(const char *arg)
{
    if (strcmp(arg, "--cli") == 0) {
        return false;
    }

    if (strcmp(arg, "--gui") != 0) {
        print_usage_exit();
    }

#ifdef GUI_SUPPORT
    return true;
#else
    cout << "This build of spicypass does not support the graphical interface. "
         << "Refer to the install instructions for further assistance. "
         << "Proceeding to the command line." << endl;
    return false;
#endif
}

void set_file_permissions(void)
{
#ifndef _WIN32
    umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
#endif
}

int main(int argc, char **argv)
{
    print_version(argv[0]);

    if (argc <= 1) {
        print_usage_exit();
    }

    bool have_gui = gui_enabled(argv[1]);

    set_file_permissions();

    if (crypto_init() != 0) {
        cerr << "crypto_init() failed" << endl;
        return -1;
    }

#ifdef GUI_SUPPORT
    GUI ui;
#endif

    Pass_Store p;
    int ret = -1;

    if (have_gui) {
        ret = 0;
    } else {
        ret = cli_new_pass_store(p);
    }

    switch (ret) {
        case 0: {
            break;
        }
        case -2: {
            cerr << "crypto_memlock() failed in new_pass_store()" << endl;
            return -1;
        }
        case -3: {
            cerr << "load_password_store() failed to open pass store file" << endl;
            return -1;
        }
        case -4: {
            cout << "Invalid password" << endl;
            return -1;
        }
        case -5: {
            cerr << "Failed to decrypt pass store file" << endl;
            return -1;
        }
        case -6: {
            cerr << "GUI failed to initialize" << endl;
            return -1;
        }
        default: {
            cerr << "Unknown error" << endl;
            return -1;
        }
    }

    thread t(store_lock_loop, ref(p));
    t.detach();

    if (have_gui) {
#ifdef GUI_SUPPORT
        gtk_init(&argc, &argv);
        ui.run(p);
#endif
    } else {
        run_cli(p);
    }

    return 0;
}
