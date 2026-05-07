cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

set(pools_test_src
    test_height_tree_level.cc
    test_leaf_height_tree.cc
    test_pools_tx_utils_branches.cc)
add_executable(pools_test ${pools_test_src})

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(pools_test PRIVATE pools db protos common gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(pools_test PRIVATE pools db protos common gtest gtest_main gmock gmock_main)
endif()
