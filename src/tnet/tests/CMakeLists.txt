cmake_minimum_required(VERSION 3.22)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ tnet_test_src)
add_executable(tnet_test ${tnet_test_src})

add_dependencies(tnet_test tnet)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(tnet_test PRIVATE tnet common gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(tnet_test PRIVATE tnet common gtest gtest_main gmock gmock_main)
endif()
