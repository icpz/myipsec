cmake_minimum_required(VERSION 3.1.10)
project(MyIpsec)

find_package(Qt5Widgets)

list(APPEND LIB_SRC
        confeditor.cpp
        myipsec.cpp
    )

list(APPEND LIB_HDR
        confeditor.h
        myipsec.h
    )

list(APPEND LIB_UI
        confeditor.ui
        myipsec.ui
    )

set(BIN_SRC main.cpp)

qt5_wrap_cpp(LIB_hdr_moc ${LIB_HDR})
qt5_wrap_ui(LIB_ui_moc ${LIB_UI})

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_BINARY_DIR})

add_library(LIBS SHARED 
    ${LIB_SRC}
    ${LIB_hdr_moc}
    ${LIB_ui_moc}
)
target_link_libraries(LIBS Qt5::Widgets)

add_executable(MyIpsec ${BIN_SRC})
target_link_libraries (MyIpsec LIBS)


