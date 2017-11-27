
find_package(PkgConfig REQUIRED)
find_package(gflags REQUIRED)

find_library(LIBEV ev)
find_library(LIBGLOG glog)
find_library(LIBMBEDCRYPT mbedcrypto)

pkg_search_module(LIBNFQUEUE REQUIRED libnetfilter_queue)

list(APPEND DEPS
    gflags
    ${LIBEV}
    ${LIBGLOG}
    ${LIBMBEDCRYPT}
    ${LIBNFQUEUE_LIBRARIES}
    )

list(APPEND SOURCES
    myipsec.cpp
    nfq.cpp
    nfqueue.cpp
    conf.cpp
    transer.cpp
    filter.cpp
    )

add_custom_target(scripts)

add_custom_command(TARGET scripts PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E
                        copy ${CMAKE_CURRENT_SOURCE_DIR}/iptables_setup.sh
                             ${CMAKE_CURRENT_BINARY_DIR}/iptables_setup.sh)

add_executable(myipsec ${SOURCES})
add_dependencies(myipsec scripts)
target_link_libraries(myipsec ${DEPS})

