#!/bin/bash

. .travis/flags.sh

# Add all warning flags we can.
add_flag -Wall
add_flag -Wextra
add_flag -Werror