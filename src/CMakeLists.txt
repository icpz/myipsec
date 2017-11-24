
find_package(PkgConfig REQUIRED)

find_library(LIBEV ev)
find_library(LIBGLOG glog)
find_library(LIBMBEDCRYPT mbedcrypto)

pkg_search_module(LIBNFQUEUE REQUIRED libnetfilter_queue)

list(APPEND DEPS
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

# add the executable
add_executable(myipsec ${SOURCES})
target_link_libraries(myipsec ${DEPS})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/iptables_setup.sh
               ${CMAKE_CURRENT_BINARY_DIR}/iptables_setup.sh
               COPYONLY)

