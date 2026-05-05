cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

set(consensus_test_src
    test_smoke.cc)
add_executable(consensus_test ${consensus_test_src})

target_link_libraries(consensus_test PRIVATE gtest gtest_main gmock gmock_main pthread dl)
