cmake_minimum_required(VERSION 3.22)

add_compile_options(-Wno-unused-parameter)

set(init_test_src
    test_command_branches.cc
    test_command_functions.cc
    test_init_utils_structs.cc
    test_http_handler.cc
    test_genesis_block_init.cc
    test_network_init.cc
    test_ws_server.cc)

add_executable(init_test ${init_test_src})

add_dependencies(init_test init)

target_link_libraries(init_test PRIVATE
    ${LINK_ARGS}
    gtest
    gtest_main
    gmock
    gmock_main
    pthread
    dl)
