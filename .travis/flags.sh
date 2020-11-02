#!/bin/bash

add_cxx_flag() { CXX_FLAGS="$CXX_FLAGS $@"; }
add_ld_flag() { LD_FLAGS="$LD_FLAGS $@"; }
add_flag() {
  add_cxx_flag "$@"
}

export LD_LIBRARY_PATH="$CACHEDIR/lib"
export PKG_CONFIG_PATH="$CACHEDIR/lib/pkgconfig"

CXX_FLAGS=""
LD_FLAGS=""

add_flag -O3 -march=native
add_flag -std=c++11
add_flag -g3
add_flag -ftrapv