cmake_minimum_required(VERSION 3.16)

project(tap-protocol LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTING "Build unit tests" OFF)
option(BUILD_TEST_WITH_EMULATOR "Build test with emulator" OFF)

if (ANDROID)
    add_library(wally SHARED IMPORTED)
    set_target_properties(wally PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/third_party/libwally-core/release/lib/${ANDROID_ABI}/libwallycore.so")
    set_target_properties(wally PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/third_party/libwally-core/release/include")

elseif(WIN32)
    message(FATAL_ERROR "Not support yet!")
else()
    add_library(secp256k1 STATIC IMPORTED)
    set_target_properties(secp256k1 PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/third_party/libwally-core/src/secp256k1/.libs/libsecp256k1.a")

    add_library(wally SHARED IMPORTED)
    set_target_properties(wally PROPERTIES IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/third_party/libwally-core/src/.libs/libwallycore.so")
    set_target_properties(wally PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/third_party/libwally-core/include")
    target_link_libraries(wally INTERFACE secp256k1)
endif()

add_library(tap-protocol STATIC
        include/tap_protocol/cktapcard.h
        include/tap_protocol/transport.h
        include/tap_protocol/tap_protocol.h
        include/tap_protocol/utils.h
        include/tap_protocol/secp256k1_utils.h
        include/tap_protocol/hash_utils.h
        include/tap_protocol/hwi_tapsigner.h
        src/utils.cpp
        src/secp256k1_utils.cpp
        src/cktapcard.cpp
        src/transport.cpp
        src/tap_protocol.cpp 
        src/secp256k1_utils.cpp
        src/hash_utils.cpp
        src/hwi_tapsigner.cpp
        )

add_subdirectory(third_party/bitcoin-core)

target_link_libraries(tap-protocol 
        PRIVATE wally bitcoin-core
        )

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
    find_package(Boost 1.47.0 REQUIRED system)
    enable_testing()
    add_library(test_main OBJECT tests/unit.cpp)

    target_include_directories(test_main
            PUBLIC ${PROJECT_SOURCE_DIR}/tests/third_party/doctest
            PUBLIC ${Boost_INCLUDE_DIRS}
            )
    target_link_libraries(test_main ${Boost_LIBRARIES})

    set(files
            tests/transport_test.cpp
            tests/connection_test.cpp
            tests/secp256k1_test.cpp
            tests/utils_test.cpp
            tests/hwi_tapsigner_test.cpp
            )
    foreach (file ${files})
        get_filename_component(testcase ${file} NAME_WE)
        add_executable(${testcase} ${file} $<TARGET_OBJECTS:test_main>)
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
