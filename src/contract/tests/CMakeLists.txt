cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

set(contract_test_src
    test_main.cc
    test_contract_manager.cc
    test_contract_identity_branches.cc
    test_contract_sha256_ripemd160_branches.cc
    test_contract_create2_branches.cc
    test_contract_modexp_blake2_branches.cc
    test_contract_alt_bn128_branches.cc
    test_contract_ecrecover_branches.cc
    test_contract_manager_branches.cc)
add_executable(contract_test ${contract_test_src})

target_link_libraries(contract_test PRIVATE contract security common gtest gtest_main gmock gmock_main pthread dl)
