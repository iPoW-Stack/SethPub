cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

set(consensus_test_src
    test_consensus_utils.cc
    test_consensus_hotstuff_zbft_surface.cc)
add_executable(consensus_test ${consensus_test_src})

target_link_libraries(
    consensus_test
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
