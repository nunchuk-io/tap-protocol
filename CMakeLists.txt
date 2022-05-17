cmake_minimum_required(VERSION 3.14)

project(tap-protocol LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTING "Build unit tests" OFF)

add_library(tap-protocol STATIC
        include/tap_protocol/cktapcard.h
        include/tap_protocol/transport.h
        include/tap_protocol/tap_protocol.h
        src/cktapcard.cpp
        src/transport.cpp
        src/tap_protocol.cpp)


#target_link_libraries(tap-protocol PUBLIC
#        )

target_include_directories("${PROJECT_NAME}" PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/third_party/include
        )

target_compile_definitions(tap-protocol PRIVATE TAPPROTOCOL_LIBRARY)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

if (BUILD_TESTING)
    enable_testing()
    add_library(unittest_main OBJECT tests/unit.cpp)

    target_include_directories(unittest_main
            PUBLIC ${PROJECT_SOURCE_DIR}/tests/third_party/doctest
            )
    set(files
            tests/transport_test.cpp
            tests/connection_test.cpp
            )
    foreach (file ${files})
        get_filename_component(testcase ${file} NAME_WE)
        add_executable(${testcase} ${file} $<TARGET_OBJECTS:unittest_main>)
        target_link_libraries(${testcase} ${PROJECT_NAME})
        target_include_directories(${testcase} PUBLIC
                "${PROJECT_SOURCE_DIR}/tests/third_party/doctest"
                "${PROJECT_SOURCE_DIR}/include"
                )
        add_test(NAME ${testcase} COMMAND ${testcase})
    endforeach ()
endif ()
