cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

# Branch/coverage tests for hotstuff types; keep heavy integration tests out unless deps allow.
set(hotstuff_test_src
    test_types.cc
    test_view_block_chain.cc
    test_smoke.cc)
add_executable(hotstuff_test ${hotstuff_test_src})

target_link_libraries(
    hotstuff_test
    PRIVATE
    consensus
    block
    elect
    timeblock
    pools
    db
    protos
    common
    security
    gtest
    gtest_main
    gmock
    gmock_main
    pthread
    dl)
