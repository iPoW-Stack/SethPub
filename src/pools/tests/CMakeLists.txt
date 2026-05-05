cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ pools_test_src)
add_executable(pools_test ${pools_test_src})

add_dependencies(pools_test pools)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(pools_test PRIVATE consensus sync sethvm block vss ck elect timeblock pools bls network broadcast dht transport contract pki big_num db security common protos tcmalloc gmp gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(pools_test PRIVATE consensus sync sethvm block vss ck elect timeblock pools bls network broadcast dht transport contract pki big_num db security common protos gmp gtest gtest_main gmock gmock_main)
endif()
