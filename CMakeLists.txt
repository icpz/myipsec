cmake_minimum_required (VERSION 3.6)
project (MyIpsec)
# The version number.
set (MYIPSEC_VERSION_MAJOR 1)
set (MYIPSEC_VERSION_MINOR 0)

add_subdirectory(src build/bin)
add_subdirectory(MyIpsec build)

