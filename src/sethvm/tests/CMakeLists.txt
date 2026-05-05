cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ sethvm_test_src)
add_executable(sethvm_test ${sethvm_test_src})

add_dependencies(sethvm_test sethvm)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(sethvm_test PRIVATE consensus sethvm contract security common gmssl protos gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(sethvm_test PRIVATE consensus sethvm contract security common gmssl protos gtest gtest_main gmock gmock_main)
endif()
