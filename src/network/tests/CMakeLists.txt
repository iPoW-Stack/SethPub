cmake_minimum_required(VERSION 3.22)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ network_test_src)
add_executable(network_test ${network_test_src})

add_dependencies(network_test network block)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(network_test PRIVATE network block broadcast dht transport security common protos gmssl gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(network_test PRIVATE network block broadcast dht transport common protos gtest gtest_main gmock gmock_main)
endif()
