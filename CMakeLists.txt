cmake_minimum_required(VERSION 3.14)

project(tap-protocol LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTING "Build unit tests" OFF)
option(BUILD_TEST_WITH_EMULATOR "Build test with emulator" OFF)

if (ANDROID)
    add_library(wally STATIC IMPORTED)
    set_target_properties(wally PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/third_party/libwally-core/android/${ANDROID_ABI}/lib/libwallycore.a")
    set_target_properties(wally PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/third_party/libwally-core/android/${ANDROID_ABI}/include")

    add_library(secp256k1 STATIC IMPORTED)
    set_target_properties(secp256k1 PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/third_party/libwally-core/android/${ANDROID_ABI}/lib/libsecp256k1.a")
    set_target_properties(secp256k1 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/third_party/libwally-core/android/${ANDROID_ABI}/include")
elseif(WIN32)
    message(FATAL_ERROR "Not support yet!")
else()
    add_library(wally STATIC IMPORTED)
    set_target_properties(wally PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/third_party/libwally-core/lib/lib/libwallycore.a")
    set_target_properties(wally PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/third_party/libwally-core/lib/include")

    add_library(secp256k1 STATIC IMPORTED)
    set_target_properties(secp256k1 PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/third_party/libwally-core/lib/lib/libsecp256k1.a")
    set_target_properties(secp256k1 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/third_party/libwally-core/lib/include")
endif()

add_library(tap-protocol STATIC
        include/tap_protocol/cktapcard.h
        include/tap_protocol/transport.h
        include/tap_protocol/tap_protocol.h
        include/tap_protocol/utils.h
        include/tap_protocol/secp256k1_utils.h
        src/utils.cpp
        src/secp256k1_utils.cpp
        src/cktapcard.cpp
        src/transport.cpp
        src/tap_protocol.cpp 
        src/secp256k1_utils.cpp)

add_subdirectory(${PROJECT_SOURCE_DIR}/third_party/cppcodec)

target_link_libraries(tap-protocol PRIVATE wally secp256k1 cppcodec)

target_include_directories(${PROJECT_NAME}
        PUBLIC ${PROJECT_SOURCE_DIR}/include
        PUBLIC ${PROJECT_SOURCE_DIR}/third_party/include
        )

target_compile_definitions(${PROJECT_NAME} PRIVATE TAPPROTOCOL_LIBRARY)

target_precompile_headers(${PROJECT_NAME}
        PRIVATE ${PROJECT_SOURCE_DIR}/third_party/include/nlohmann/json.hpp)

#set(CPACK_PROJECT_NAME ${PROJECT_NAME})
#set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
#include(CPack)

if (BUILD_TESTING)
    enable_testing()
    add_library(unittest_main OBJECT tests/unit.cpp)

    target_include_directories(unittest_main
            PUBLIC ${PROJECT_SOURCE_DIR}/tests/third_party/doctest
            )

    set(files
            tests/transport_test.cpp
            tests/connection_test.cpp
            tests/secp256k1_test.cpp
            tests/utils_test.cpp
            )
    foreach (file ${files})
        get_filename_component(testcase ${file} NAME_WE)
        add_executable(${testcase} ${file} $<TARGET_OBJECTS:unittest_main>)
        target_link_libraries(${testcase} ${PROJECT_NAME})
        target_include_directories(${testcase} PUBLIC
                "${PROJECT_SOURCE_DIR}/tests/third_party/doctest"
                "${PROJECT_SOURCE_DIR}/include"
                )
        if (BUILD_TEST_WITH_EMULATOR)
            target_compile_definitions(${testcase} PRIVATE BUILD_TEST_WITH_EMULATOR)
        endif ()

        add_test(NAME ${testcase} COMMAND ${testcase})
    endforeach ()
endif ()
