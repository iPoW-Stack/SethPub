cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

set(hotstuff_test_src
    test_smoke.cc)
add_executable(hotstuff_test ${hotstuff_test_src})

target_link_libraries(hotstuff_test PRIVATE gmp gmpxx gtest gtest_main gmock gmock_main pthread dl)
