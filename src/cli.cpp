/*  cli.cpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
 */

#include "load.hpp"
#include "password.hpp"
#include "util.hpp"
#include "crypto.hpp"
#include "cli.hpp"

typedef enum {
    OPT_EXIT = 0,
    OPT_ADD,
    OPT_REMOVE,
    OPT_FETCH,
    OPT_LIST,
    OPT_GENERATE,
    OPT_PASSWORD,
    OPT_EXPORT,
    OPT_PRINT,
} Options;


/* Prompts password and puts it in `password` array.
 *
 * Return 0 on success.
 * Return -1 input is invalid.
 */
static int prompt_password(unsigned char *password, size_t max_length)
{
    cout << "Enter master password: ";

    char pass_buf[MAX_STORE_PASSWORD_SIZE + 2];
    const char *input = fgets(pass_buf, sizeof(pass_buf), stdin);

    if (input == NULL) {
        cout << "Invalid input." << endl;
        crypto_memwipe((unsigned char *) pass_buf, sizeof(pass_buf));
        return -1;
    }

    const size_t pass_length = strlen(pass_buf);

    if (pass_length > max_length) {
        crypto_memwipe((unsigned char *) pass_buf, sizeof(pass_buf));
        return -1;
    }

    memcpy(password, pass_buf, pass_length);
    password[pass_length] = 0;

    crypto_memwipe((unsigned char *) pass_buf, sizeof(pass_buf));

    return 0;
}

static int new_password_prompt(Pass_Store &p, unsigned char *password, size_t max_length)
{
    while (true) {
        cout << "Enter new master password: ";

        // buffers are oversized by one byte for proper error reporting due to fgets weirdness
        char pass1[MAX_STORE_PASSWORD_SIZE + 3];
        char pass2[MAX_STORE_PASSWORD_SIZE + 3];

        const char *input1 = fgets(pass1, sizeof(pass1), stdin);
        cout << endl;

        if (p.check_lock()) {
            crypto_memwipe((unsigned char *) pass1, sizeof(pass1));
            return PASS_STORE_LOCKED;
        }

        if (input1 == NULL) {
            cout << "Invalid input" << endl;
            crypto_memwipe((unsigned char *) pass1, sizeof(pass1));
            continue;
        }

        const size_t pass_length = strlen(pass1);

        if (pass_length < MIN_MASTER_PASSWORD_SIZE || pass_length > max_length) {
            cout << "Password must be between " << MIN_MASTER_PASSWORD_SIZE  << " and " << (max_length - 1) << " characters long" <<
                 endl;
            continue;
        }

        cout << "Enter password again: ";

        const char *input2 = fgets(pass2, sizeof(pass2), stdin);
        cout << endl;

        if (p.check_lock()) {
            crypto_memwipe((unsigned char *) pass1, sizeof(pass1));
            crypto_memwipe((unsigned char *) pass2, sizeof(pass2));
            return PASS_STORE_LOCKED;
        }

        if (input2 == NULL) {
            cout << "Invalid input" << endl;
            crypto_memwipe((unsigned char *) pass1, sizeof(pass1));
            crypto_memwipe((unsigned char *) pass2, sizeof(pass2));
            continue;
        }

        if (strcmp(pass1, pass2) != 0) {
            cout << "New passwords don't match" << endl;
            crypto_memwipe((unsigned char *) pass1, sizeof(pass1));
            crypto_memwipe((unsigned char *) pass2, sizeof(pass2));
            continue;
        }

        memcpy(password, pass1, pass_length);
        password[pass_length] = 0;

        crypto_memwipe((unsigned char *) pass1, sizeof(pass1));
        crypto_memwipe((unsigned char *) pass2, sizeof(pass2));

        return 0;
    }
}

/*
 * Initializes pass store file with password hash on first run. Puts new password in
 * the `password` buffer.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Return PASS_STORE_LOCKED if pass store is locked.
 */
static int init_new_password(Pass_Store &p, unsigned char *password, size_t max_length)
{
    terminal_echo(false);
    const int ret = new_password_prompt(p, password, max_length);
    terminal_echo(true);

    if (ret == PASS_STORE_LOCKED) {
        return ret;
    }

    cout << "Generating new encryption key. This can take a while" << endl;

    if (init_pass_hash(p, password, strlen((char *) password)) != 0) {
        cerr << "init_pass_hash() failed." << endl;
        return -1;
    }

    return 0;
}

/*
 * Prompts user to update password for pass store file.
 *
 * Return 0 on success.
 * Return -1 on failure.
 * Return PASS_STORE_LOCKED if pass store is locked.
 */
static int change_password_prompt(Pass_Store &p)
{
    unsigned char new_password[MAX_STORE_PASSWORD_SIZE + 2];

    cout << "Changing master password. Enter q to go back." << endl;

    while (true) {
        cout << "Enter old password: ";

        char old_pass[MAX_STORE_PASSWORD_SIZE + 2];
        const char *input1 = fgets(old_pass, sizeof(old_pass), stdin);
        cout << endl;

        if (p.check_lock()) {
            crypto_memwipe((unsigned char *) old_pass, sizeof(old_pass));
            return PASS_STORE_LOCKED;
        }

        if (input1 == NULL) {
            cout << "Invalid input" << endl;
            crypto_memwipe((unsigned char *) old_pass, sizeof(old_pass));
            continue;
        }

        if (strcmp(old_pass, "q\n") == 0) {
            crypto_memwipe((unsigned char *) old_pass, sizeof(old_pass));
            return -1;
        }

        cout << "Validating password..." << endl;

        const size_t pass_length = strlen(old_pass);

        if (!p.validate_password((unsigned char *) old_pass, pass_length)) {
            cout << "Invalid password" << endl;
            crypto_memwipe((unsigned char *) old_pass, sizeof(old_pass));
            continue;
        }

        break;
    }

    if (new_password_prompt(p, new_password, sizeof(new_password) - 1) == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    cout << "Generating new encryption key..." << endl;

    const int ret = update_crypto(p, new_password, strlen((char *) new_password));

    crypto_memwipe(new_password, sizeof(new_password));

    if (ret == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    if (ret < 0) {
        cerr << "Failed to update password (error code: " << to_string(ret) << ")" << endl;
        return -1;
    }

    cout << "Successfully updated password" << endl;

    return 0;
}

static int new_password(Pass_Store &p)
{
    terminal_echo(false);
    const int ret = change_password_prompt(p);
    terminal_echo(true);

    return ret;
}

static int add(Pass_Store &p)
{
    string key, password, note;

    cout << "Enter key to add: ";
    getline(cin, key);

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    if (key.length() > MAX_STORE_KEY_SIZE) {
        cout << "Key is too long" << endl;
        return -1;
    }

    if (key.length() == 0) {
        cout << "Invalid key" << endl;
        return -1;
    }

    if (!string_printable(key)) {
        cout << "Key may only contain printable ASCII characters" << endl;
        return -1;
    }

    cout << "Enter password (leave empty for a random password): ";
    getline(cin, password);

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    if (password.length() > MAX_STORE_PASSWORD_SIZE) {
        cout << "Password length must not exceed " << to_string(MAX_STORE_PASSWORD_SIZE) << " characters" << endl;
        return -1;
    }

    if (password.empty()) {
        vector<char> rand_pass = random_password(16U);

        if (password_invalid(rand_pass)) {
            cout << "Failed to generate random password" << endl;
            return -1;
        }

        password = string(rand_pass.begin(), rand_pass.end());
        crypto_memwipe((unsigned char *) rand_pass.data(), rand_pass.size());

        if (password.empty()) {
            cout << "Failed to generate random password" << endl;
            return -1;
        }
    } else if (!string_printable(password)) {
        cout << "Password may only contain printable ASCII characters" << endl;
        return -1;
    }

    cout << "Enter note (optional): ";
    getline(cin, note);

    const int exists = p.key_exists(key);

    if (exists == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    if (exists > 0) {
        while (true) {
            string s;
            cout << "Key \"" << key << "\" already exists. Overwrite? Y/n ";
            getline(cin, s);

            if (s == "Y" || s == "y") {
                break;
            } else if (s == "N" || s == "n") {
                return 0;
            }
        }
    }

    if (p.insert(key, password, note) != 0) {
        cout << "Failed to add entry" << endl;
        return -1;
    }

    const int ret = save_password_store(p);

    switch (ret) {
        case 0: {
            cout << "Added new entry with key \"" << key << "\"" << endl;
            return 0;
        }

        case -1: {
            cerr << "Failed to save password store: Failed to open pass store file" << endl;
            return -1;
        }

        case -2: {
            cerr << "Failed to save password store: Encryption error" << endl;
            return -1;
        }

        case -3: {
            cerr << "Failed to save password store: File save error" << endl;
            return -1;
        }

        case -4: {
            cerr << "Failed to save password store: read-only mode is enabled" << endl;
            return -1;
        }

        default: {
            cerr << "Failed to save password store: Unknown error" << endl;
            return -1;
        }
    }
}

static int remove(Pass_Store &p)
{
    string key;
    cout << "Enter key to remove: ";
    getline(cin, key);

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    while (true) {
        cout << "Are you sure you want to remove the key \"" << key << "\" ? Y/n ";
        string s;
        getline(cin, s);

        if (p.check_lock()) {
            return PASS_STORE_LOCKED;
        }

        if (s == "y" || s == "Y") {
            break;
        } else if (s == "n" || s == "N") {
            return 0;
        }

        cout << "Invalid option" << endl;
    }

    const int removed = p.remove(key);

    if (removed == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    if (removed != 0) {
        cout << "Key not found" << endl;
        return -1;
    }

    cout << "Removed \"" << key << "\" from pass store" << endl;

    const int ret = save_password_store(p);

    if (ret != 0) {
        cerr << "Failed to save password store (error code: " << to_string(ret) << ")" << endl;
        return -1;
    }

    return 0;
}

static int fetch(Pass_Store &p)
{
    cout << "Enter key: ";

    string key;
    getline(cin, key);

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    if (key.empty()) {
        return -1;
    }

    vector<tuple<string, const char *, const char *>> result;
    const int matches = p.get_matches(key, result, false);

    if (matches == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    if (result.empty()) {
        cout << "Key not found" << endl;
        return -1;
    }

    p.s_lock();

    for (const auto &item : result) {
        cout << "Key: " << get<0>(item) << endl;
        cout << "Pass: " << get<1>(item) << endl;

        const char *note = get<2>(item);

        if (note != NULL) {
            cout << "Note: " << note << "\n" << endl;
        }
    }

    p.s_unlock();

    return 0;
}

static int list(Pass_Store &p)
{
    vector<tuple<string, const char *, const char *>> result;
    const int matches = p.get_matches("", result, false);

    if (matches == PASS_STORE_LOCKED) {
        return PASS_STORE_LOCKED;
    }

    for (const auto &item : result) {
        cout << get<0>(item) << endl;
    }

    return 0;
}

static int generate(Pass_Store &p)
{
    string input;
    int size = 0;

    while (true) {
        cout << "Enter password length: ";
        getline(cin, input);

        if (p.check_lock()) {
            return PASS_STORE_LOCKED;
        }

        try {
            size = stoi(input);
        } catch (const exception &) {
            cout << "Invalid input" << endl;
            continue;
        }

        if (size >= NUM_RAND_PASS_MIN_CHARS && size <= NUM_RAND_PASS_MAX_CHARS) {
            break;
        }

        cout << "Password must be between " << to_string(NUM_RAND_PASS_MIN_CHARS) << " and " << to_string(
                 NUM_RAND_PASS_MAX_CHARS) << " characters in length" << endl;
    }

    vector<char> pass = random_password(size);

    if (password_invalid(pass)) {
        cout << "Failed to generate password" << endl;
        return -1;
    }

    const char *pass_str = pass.data();

    cout << pass_str << endl;

    crypto_memwipe((unsigned char *) pass.data(), pass.size());

    return 0;
}

static bool unlock_prompt(Pass_Store &p)
{
    cout << "Enter master password: ";

    unsigned char pass[MAX_STORE_PASSWORD_SIZE + 2];
    const char *input = fgets((char *) pass, sizeof(pass), stdin);
    cout << endl;

    if (input == NULL) {
        cout << "Invalid input" << endl;
        crypto_memwipe(pass, sizeof(pass));
        return false;
    }

    cout << "Decrypting pass store file..." << endl;

    const int ret = load_password_store(p, pass, strlen((char *) pass));

    crypto_memwipe(pass, sizeof(pass));

    if (ret >= 0) {
        return true;
    }

    switch (ret) {
        case -1: {
            cerr << "Pass store file cannot be read" << endl;
            break;
        }

        case -2: {
            cout << "Invalid password" << endl;
            break;
        }

        case -3: {
            cerr << "Failed to decrypt pass store file" << endl;
            break;
        }

        case -4: {
            cerr << "Pass store file has bad format" << endl;
            break;
        }

        default: {
            cerr << "load_password_store() returned unknown error: " << to_string(ret) << endl;
            break;
        }
    }

    return false;
}

static void lock_check(Pass_Store &p)
{
    terminal_echo(false);

    while (!unlock_prompt(p))
        ;

    terminal_echo(true);
}

static void print_menu(void)
{
    cout << "Menu:" << endl;
    cout << "[" << to_string(OPT_ADD)        << "] Add entry" << endl;
    cout << "[" << to_string(OPT_REMOVE)     << "] Remove entry" << endl;
    cout << "[" << to_string(OPT_FETCH)      << "] Fetch entry" << endl;
    cout << "[" << to_string(OPT_LIST)       << "] List all entries" << endl;
    cout << "[" << to_string(OPT_GENERATE)   << "] Generate password" << endl;
    cout << "[" << to_string(OPT_PASSWORD)   << "] Change master password" << endl;
    cout << "[" << to_string(OPT_EXPORT)     << "] Export entries to plaintext file" << endl;
    cout << "[" << to_string(OPT_PRINT)      << "] Print menu" << endl;
    cout << "[" << to_string(OPT_EXIT)       << "] Exit" << endl;
}

static int export_entries(Pass_Store &p)

{
    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    const string export_filename = p.get_save_file() + EXPORT_FILE_EXTENTION;
    const string export_path = get_store_path(export_filename, false, p.using_custom_profile());

    if (export_path.size() == 0) {
        cerr << "Failed to export pass store." << endl;
        return -1;
    }

    cout << "WARNING: You are about to create a file on your disk that contains all "
         "of your passwords. The file will not be encrypted and can be viewed by "
         "anyone with access to this device.\n" << endl;

    unsigned char password[MAX_STORE_PASSWORD_SIZE + 2];

    terminal_echo(false);
    const int pw_ret = prompt_password(password, sizeof(password) - 1);
    terminal_echo(true);

    cout << endl;

    if (pw_ret != 0) {
        cerr << "Invalid password." << endl;
        return -1;
    }

    if (!p.validate_password(password, strlen((char *) password))) {
        cout << "Invalid password." << endl;
        return -1;
    }

    if (export_pass_store_to_plaintext(p, export_path) != 0) {
        cerr << "Failed to export pass store." << endl;
        return -1;
    }

    cout << "Exported pass store entries to plaintext file: " << export_path << endl;

    return 0;
}

/*
 * Executes command indicated by `option`.
 *
 * Return 0 on normal execution (including errors).
 * Return -1 on exit command.
 * Return PASS_STORE_LOCKED if pass store is locked.
 */
static int execute(const int option, Pass_Store &p)
{
    if (option == OPT_EXIT) {
        return -1;
    }

    if (p.check_lock()) {
        return PASS_STORE_LOCKED;
    }

    int ret = 0;

    switch (option) {
        case OPT_ADD: {
            ret = add(p);
            break;
        }

        case OPT_REMOVE: {
            ret = remove(p);
            break;
        }

        case OPT_FETCH: {
            ret = fetch(p);
            break;
        }

        case OPT_LIST: {
            ret = list(p);
            break;
        }

        case OPT_GENERATE: {
            ret = generate(p);
            break;
        }

        case OPT_PASSWORD: {
            ret = new_password(p);
            break;
        }

        case OPT_EXPORT: {
            ret = export_entries(p);
            break;
        }

        case OPT_PRINT: {
            print_menu();
            break;
        }

        default: {
            cout << "Invalid command. Enter " << to_string(OPT_PRINT) << " to print menu." << endl;
            break;
        }
    }

    return (ret != PASS_STORE_LOCKED) ? 0 : PASS_STORE_LOCKED;
}

static int command_prompt(void)
{
    cout << "> ";
    string prompt;
    getline(cin, prompt);

    try {
        return stoi(prompt);
    } catch (const exception &e) {
        return -1;
    }
}

int cli_new_pass_store(Pass_Store &p)
{
    unsigned char password[MAX_STORE_PASSWORD_SIZE + 2];

    if (first_time_run(p)) {
        cout << "Creating a new profile. " << endl;

        if (init_new_password(p, password, sizeof(password) - 1) != 0) {
            return -1;
        }
    } else {
        terminal_echo(false);
        const int pw_ret = prompt_password(password, sizeof(password) - 1);
        terminal_echo(true);

        cout << endl;

        if (pw_ret != 0) {
            return -1;
        }
    }

    cout << "Decrypting pass store file..." << endl;

    const int ret = load_password_store(p, password, strlen((char *) password));

    crypto_memwipe(password, sizeof(password));

    if (ret >= 0) {
        cout << "Loaded " << to_string(ret) << " entries" << endl;
        return 0;
    }

    switch (ret) {
        case -1: {
            return -3;
        }

        case -2: {
            return -4;
        }

        case -3: {
            return -5;
        }

        case -4: {
            return -3;
        }

        default: {
            return -3;
        }
    }
}

static void menu_loop(Pass_Store &p)
{
    print_menu();

    while (true) {
        const int option = command_prompt();
        const int ret = execute(option, p);

        switch (ret) {
            case 0: {
                break;
            }

            case PASS_STORE_LOCKED: {
                lock_check(p);
                print_menu();
                break;
            }

            default: {
                return;
            }
        }
    }
}

void run_cli(Pass_Store &p)
{
    menu_loop(p);
    clear_console();
}
