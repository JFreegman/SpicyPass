[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a82931607165486a96dfe18554e3a5d7)](https://app.codacy.com/gh/JFreegman/SpicyPass?utm_source=github.com&utm_medium=referral&utm_content=JFreegman/SpicyPass&utm_campaign=Badge_Grade)
[![CodeFactor](https://www.codefactor.io/repository/github/jfreegman/spicypass/badge)](https://www.codefactor.io/repository/github/jfreegman/spicypass)
<a href="https://scan.coverity.com/projects/jfreegman-spicypass">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/20491/badge.svg"/>
</a>

**SpicyPass** is a light-weight password manager that utilizes state of the art cryptography and minimalist design principles for secure and simple password storage.

[![Spicypass Screenshot](https://i.imgur.com/L7ezEJd.png "Main Window")](https://i.imgur.com/L7ezEJd.png)

## Features
* Both a command-line and graphical interface to choose from
* An idle lock that prompts the user for their password after a period of inactivity
* A cryptographically secure random password generator that maximizes entropy
* The ability to copy passwords to the clipboard without revealing them on the screen
* Data is automatically encrypted on disk - no setup required
* Completely offline and free of any potential internet-facing attack vectors


## Install
### Dependencies
You will need to [install](https://download.libsodium.org/doc/installation) the `libsodium` cryptography library (version >= 1.0.13). If you wish to compile with support for the graphical interface you will additionally need the `GTK3` development library (version >= 3.0).

On Unix-like systems you will also need `cmake` (version >= 3.10) and `pkg-config`. To compile, you will need either `gcc` (version >= 7.0) or `clang` (version >= 5.0). Other modern C++ compilers will probably work but are not officially supported.

### Building
#### Unix-like systems
Once you have all the dependencies installed on your system, clone this repository and navigate to its base directory. Execute the following commands:

1. `mkdir _build && cd _build`
2. `cmake ..`
3. `cmake --build .`
4. `sudo make install`

SpicyPass defaults to the release build. To build with debug symbols endabled and compiler optimizations disabled, run:

`cmake -D BUILD_TYPE=DEBUG ..`

#### Windows
Windows is presently in an experimental stage and only has support for the command line interface. The CMake configuration does not currently support Windows, and only static builds of libsodium work. Building natively with Microsoft� Visual Studio� is straight-forward. Just be sure to set the appropriate libsodium headers and static libraries, and set the language standard to C++17.

### Uninstall
There is no uninstall command. However you can manually uninstall SpicyPass by deleting all of the files listed in the `install_manifest.txt` file, which resides in the `_build` directory.

## Security
### Cryptography
All cryptography functions are supplied by the open source [libsodium](https://libsodium.org) library.

On first run, a 256-bit secret key is derived from a master password along with a randomly generated 128-bit salt using the [Argon2id v1.3](https://en.wikipedia.org/wiki/Argon2) hash algorithm. This algorithm was designed to resist brute force and side-channel attacks. All subsequent logins will require the master password.

Data is encrypted with the [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) symmetric cipher and authenticated with the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) message authentication code. When combined, these algorithms ensure both the security and integrity of the pass store file contents.

### Memory Safety
All sensitive data, including passwords and private keys, are only held in memory when necessary. When SpicyPass is closed, all sensitive data is securely wiped from memory. If SpicyPass is left running idle, all sensitive data is securely wiped from memory, and the user will be prompted for their master password in order to continue their session. These features ensure that if intruders get access to your device they will be unable to access your information through a running session or by inspecting the device's memory.

### The Pass Store File
All program data is stored in a single file named `.spicypass`. On Unix-like systems this file is located in the `$HOME` directory. On Windows it's located in `$HOMEPATH`. A plaintext header comprised of the hash of the master password and its associated salt is placed at the beginning of the file. This header does not need to be kept secret. However, if it is lost or corrupted (or if you forget the master password) all of your passwords will be lost in time, like tears in the rain. **IT IS CRITICALLY IMPORTANT TO BACK THIS FILE UP REGULARLY.**

## Known Bugs
On Windows systems spicypass has only been tested with `cmd.exe`. Other terminal emulators may be buggy or not work at all.
