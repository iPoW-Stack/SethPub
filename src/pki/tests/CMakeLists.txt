cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ pki_test_src)
add_executable(pki_test ${pki_test_src})

add_dependencies(pki_test pki)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(pki_test PRIVATE pki gmssl pbc gmp fmt ssl crypto pthread dl gtest gtest_main gmock gmock_main)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(pki_test PRIVATE pki gtest gtest_main gmock gmock_main)
endif()
