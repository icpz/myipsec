cmake_minimum_required(VERSION 3.1.10)
project(MyIpsec)

find_package(Qt5Widgets REQUIRED)

list(APPEND LIB_SRC
        confeditor.cpp
        logdialog.cpp
        myipsec.cpp
        main.cpp
    )

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR})
include_directories(${Qt5Widgets_INCLUDE_DIRS})

add_executable(MyIpsec ${LIB_SRC})
target_link_libraries(MyIpsec Qt5::Widgets)

