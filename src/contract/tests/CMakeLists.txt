cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

set(contract_test_src
    test_smoke.cc)
add_executable(contract_test ${contract_test_src})

target_link_libraries(contract_test PRIVATE gtest gtest_main gmock gmock_main pthread dl)
