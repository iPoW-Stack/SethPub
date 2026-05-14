cmake_minimum_required(VERSION 3.22)

add_compile_options(-Wno-unused-parameter)

add_executable(pools_integration_test test_pools_integration_scaffold.cc)

target_compile_definitions(pools_integration_test PRIVATE BUILD_POOLS_INTEGRATION_TEST=1)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(
        pools_integration_test
        PRIVATE
        ${LINK_ARGS}
        gtest
        gtest_main
        gmock
        gmock_main
        pthread
        dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(
        pools_integration_test
        PRIVATE
        ${LINK_ARGS}
        gtest
        gtest_main
        gmock
        gmock_main)
endif()
