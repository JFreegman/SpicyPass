cmake_minimum_required(VERSION 3.10)

project(SpicyPass)

set(SPICYPASS_INSTALL_DIRECTORY ${CMAKE_INSTALL_PREFIX}/share/spicypass)
set(GLADE_FILE_PATH ${SPICYPASS_INSTALL_DIRECTORY}/gui.glade)
set(SpicyPass_LOGO_FILE_PATH ${SPICYPASS_INSTALL_DIRECTORY}/spicypass.svg)

set(SpicyPass_VERSION_MAJOR "0")
set(SpicyPass_VERSION_MINOR "7")
set(SpicyPass_VERSION_PATCH "5")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CLANG_MINIMUM_VERSION 5.0)
set(GCC_MINIMUM_VERSION 7.0)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS GCC_MINIMUM_VERSION)
    message(FATAL_ERROR "Minimum gcc version is ${GCC_MINIMUM_VERSION}")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS CLANG_MINIMUM_VERSION)
    message(FATAL_ERROR "Minimum Clang version is ${CLANG_MINIMUM_VERSION}")
endif()

configure_file(SpicyPassConfig.h.in SpicyPassConfig.h)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBSODIUM REQUIRED libsodium)
pkg_check_modules(GTK gtk+-3.0)

find_package(Threads REQUIRED)

if(NOT GTK_FOUND)
    message(WARNING "GTK3 library not found. Compiling without GUI support.")
else()
    add_definitions(-DGUI_SUPPORT ${GTK_DEFINITIONS})
    set(GUI_INSTALL_FILES gui/gui.glade icon/spicypass.svg)
endif(NOT GTK_FOUND)

add_executable(spicypass src/cli.cpp
                         src/cli.hpp
                         src/crypto.cpp
                         src/crypto.hpp
                         src/gui.cpp
                         src/gui.hpp
                         src/load.cpp
                         src/load.hpp
                         src/password.cpp
                         src/password.hpp
                         src/spicy.cpp
                         src/spicy.hpp
                         src/util.cpp
                         src/util.hpp
                         )

target_link_libraries(spicypass Threads::Threads
                                ${LIBSODIUM_LIBRARIES}
                                ${GTK_LIBRARIES}
                                )

target_include_directories(spicypass PUBLIC ${LIBSODIUM_INCLUDE_DIRS}
                                            ${GTK_INCLUDE_DIRS}
                                            )

target_compile_options(spicypass PUBLIC ${LIBSODIUM_CFLAGS_OTHER}
                                        ${GTK_CFLAGS_OTHER}
                                        )

if(NOT BUILD_TYPE)
    set(BUILD_TYPE RELEASE)
endif()

if(BUILD_TYPE MATCHES RELEASE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Wno-deprecated -O2 -fstack-protector-all")
elseif(BUILD_TYPE MATCHES DEBUG)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Wno-deprecated -O0 -g -fstack-protector-all -DDEBUG")
else()
    message(FATAL_ERROR "Unsupported build type: ${BUILD_TYPE}")
endif()

message(STATUS "Build type: ${BUILD_TYPE}")

target_include_directories(spicypass PUBLIC "${SpicyPass_BINARY_DIR}")

install(TARGETS spicypass DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
install(FILES ${GUI_INSTALL_FILES} DESTINATION ${SPICYPASS_INSTALL_DIRECTORY})

# Packaging

SET(CPACK_PACKAGE_VERSION ${SpicyPass_VERSION_MAJOR}.${SpicyPass_VERSION_MINOR}.${SpicyPass_VERSION_PATCH})

if("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Darwin")
    SET(CPACK_GENERATOR "DragNDrop")
elseif("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Linux")
    SET(CPACK_GENERATOR "DEB")
else()
    message(FATAL_ERROR "Packaging does not support system: ${CMAKE_HOST_SYSTEM_NAME}")
endif()

SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "jfreegman@gmail.com")
SET(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/JFreegman/SpicyPass")
SET(CPACK_DEBIAN_PACKAGE_DESCRIPTION "SpicyPass is a light-weight password manager that utilizes state of the art cryptography and minimalist design principles for secure and simple password storage.")

INCLUDE(CPack)
