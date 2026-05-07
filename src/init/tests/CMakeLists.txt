cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

set(init_test_src
    test_command_branches.cc
    test_init_utils_structs.cc)
add_executable(init_test ${init_test_src})

add_dependencies(init_test init)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(init_test PRIVATE ${LINK_ARGS} gmssl uv gtest gtest_main gmock gmock_main)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(init_test PRIVATE ${LINK_ARGS} uv gtest gtest_main gmock gmock_main)
endif()
