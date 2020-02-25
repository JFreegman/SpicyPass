cmake_minimum_required(VERSION 3.10)

project(BasedPass)

set(BasedPass_VERSION_MAJOR "0")
set(BasedPass_VERSION_MINOR "2")
set(BasedPass_VERSION_PATCH "0")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

configure_file(BasedPassConfig.h.in BasedPassConfig.h)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBSODIUM REQUIRED libsodium)

add_executable(basedpass src/based.cpp
                         src/based.hpp
                         src/util.cpp
                         src/util.hpp
                         src/crypto.cpp
                         src/crypto.hpp
                         src/password.cpp
                         src/password.hpp
                         src/load.cpp
                         src/load.hpp
                         )

target_link_libraries(basedpass ${LIBSODIUM_LIBRARIES})
target_include_directories(basedpass PUBLIC ${LIBSODIUM_INCLUDE_DIRS})
target_compile_options(basedpass PUBLIC ${LIBSODIUM_CFLAGS_OTHER})

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(CMAKE_BUILD_TYPE MATCHES Release)
    set(CMAKE_CXX_FLAGS "${CAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -O2 -fstack-protector-all")
elseif(CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_CXX_FLAGS "${CAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -O0 -g -fstack-protector-all -DDEBUG")
else()
    message(FATAL_ERROR "Unsupported build type: ${CMAKE_BUILD_TYPE}")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

target_include_directories(basedpass PUBLIC "${BasedPass_BINARY_DIR}")

install(TARGETS basedpass DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
