
find_package(PkgConfig REQUIRED)

find_library(LIBEV ev)
find_library(LIBGLOG glog)

pkg_search_module(LIBNFQUEUE REQUIRED libnetfilter_queue)

list(APPEND DEPS
    ${LIBEV}
    ${LIBGLOG}
    ${LIBNFQUEUE_LIBRARIES}
    )

list(APPEND SOURCES
    myipsec.cpp
    nfq.cpp
    nfqueue.cpp
    )

# add the executable
add_executable(myipsec ${SOURCES})
target_link_libraries(myipsec ${DEPS})

