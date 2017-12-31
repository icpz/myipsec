cmake_minimum_required(VERSION 3.2)
project(MyIpsec)

set(CMAKE_CXX_STANDARD 14)

# The version number.
set(MYIPSEC_VERSION_MAJOR 1)
set(MYIPSEC_VERSION_MINOR 0)

option(BUILD_WITH_STATIC "linking core service binary static" OFF)

add_subdirectory(src build/bin)
add_subdirectory(MyIpsec build)

