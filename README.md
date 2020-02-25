# BasedPass
BasedPass is a minimalist command-line password manager that utilizes secret key encryption for secure and simple password storage. It comes equipped with a cryptographically secure random password generator.

## Install
### Dependencies
In order to build BasedPass you will need `cmake` (version >= 3.10) and `pkg-config`.

You will also need to [install](https://download.libsodium.org/doc/installation) the libsodium cryptography library (version >= 1.0.13) .

### Building
#### Unix-like systems
once you have all the dependencies installed on your system, clone this repository and navigate to its base directory.

Now type the following commands:

1. `mkdir _build && cd _build`
2. `cmake ..`
3. `cmake --build .`
4. `sudo make install`

#### Windows and OSX
Coming soon?

### Uninstall
There is no uninstall command. However you can manually uninstall BasedPass by deleting all of the files listed in the `install_manifest.txt` file, which resides in the `_build` directory.

## Security Details
All cryptography functions are supplied by the [libsodium](https://libsodium.org) cryptography library.

On first run, a 256-bit secret key is derived from a master password along with a randomly generated 128-bit salt using the [Argon2id v1.3](https://en.wikipedia.org/wiki/Argon2) hash algorithm. This algorithm was chosen on account of it being designed to resist brute force and side-channel attacks.

The pass store file is encrypted with the [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) symmetric cipher and authenticated with the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) message authentication code. When combined, these algorithms ensure both the security and integrity of the pass store file contents.

A plaintext header comprised of the hash of the master password and its associated salt is placed at the beginning of the pass store file. This header does not need to be kept secret. However, if it is lost or corrupted (or if you forget the master password) all of your passwords will be lost in time, like tears in the rain.
