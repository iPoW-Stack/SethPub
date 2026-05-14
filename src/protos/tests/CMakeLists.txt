cmake_minimum_required(VERSION 3.22)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ protos_test_src)
add_executable(protos_test ${protos_test_src})

add_dependencies(protos_test protos)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(protos_test PRIVATE protos pools common db gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(protos_test PRIVATE protos pools common db gtest gtest_main gmock gmock_main)
endif()
