cmake_minimum_required(VERSION 3.1.10)
project(MyIpsec)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Qt5Core REQUIRED)
find_package(Qt5Widgets REQUIRED)
find_package(Threads REQUIRED)

list(APPEND LIB_SRC
        confeditor.cpp
        logdialog.cpp
        myipsec.cpp
        main.cpp
    )

if(BUILD_WITH_STATIC)
    list(APPEND LIBS
            png
            harfbuzz
            m
            z
            icui18n
            icuuc
            icudata
            libglib-2.0.a
            dl
            qtpcre2
        )
else(BUILD_WITH_STATIC)
    list(APPEND LIBS)
endif(BUILD_WITH_STATIC)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR})
include_directories(${Qt5Widgets_INCLUDE_DIRS})

add_executable(MyIpsec ${LIB_SRC})
target_link_libraries(MyIpsec Qt5::Core Qt5::Widgets Threads::Threads ${LIBS})

