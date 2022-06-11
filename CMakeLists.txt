cmake_minimum_required(VERSION 3.16)

project(tap-protocol LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTING "Build unit tests" OFF)
option(BUILD_SHARED_LIB_TAPPROTOCOL "Build as shared library" ON)

set(${PROJECT_NAME}_HEADERS
        include/tap_protocol/cktapcard.h
        include/tap_protocol/transport.h
        include/tap_protocol/tap_protocol.h
        include/tap_protocol/utils.h
        include/tap_protocol/secp256k1_utils.h
        include/tap_protocol/hash_utils.h
        include/tap_protocol/hwi_tapsigner.h
        )

set(${PROJECT_NAME}_SOURCES 
        src/utils.cpp
        src/secp256k1_utils.cpp
        src/cktapcard.cpp
        src/transport.cpp
        src/secp256k1_utils.cpp
        src/hash_utils.cpp
        src/hwi_tapsigner.cpp
        )

if (${BUILD_SHARED_LIB_TAPPROTOCOL}) 
  add_library(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_HEADERS} ${${PROJECT_NAME}_SOURCES})
else()
  add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_HEADERS} ${${PROJECT_NAME}_SOURCES})
endif()

if (UNIX AND ${BUILD_SHARED_LIB_TAPPROTOCOL})
  add_compile_options(-fPIC)
endif()

add_subdirectory(contrib/bitcoin-core)

target_link_libraries(${PROJECT_NAME} 
        PRIVATE bitcoin-core
        )

target_include_directories(${PROJECT_NAME}
        PUBLIC ${PROJECT_SOURCE_DIR}/include
        PUBLIC ${PROJECT_SOURCE_DIR}/contrib/include
        )

target_compile_definitions(${PROJECT_NAME} PRIVATE TAPPROTOCOL_LIBRARY)

target_precompile_headers(${PROJECT_NAME}
        PRIVATE ${PROJECT_SOURCE_DIR}/contrib/include/nlohmann/json.hpp)

#set(CPACK_PROJECT_NAME ${PROJECT_NAME})
#set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
#include(CPack)

if (BUILD_TESTING)
    find_package(Boost 1.47.0 REQUIRED system)
    enable_testing()
    add_library(test_main OBJECT tests/unit.cpp)

    target_include_directories(test_main
            PUBLIC ${PROJECT_SOURCE_DIR}/tests/contrib/doctest
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
                "${PROJECT_SOURCE_DIR}/tests/contrib/doctest"
                "${PROJECT_SOURCE_DIR}/include"
                )

        add_test(NAME ${testcase} COMMAND ${testcase})
    endforeach ()
endif ()
