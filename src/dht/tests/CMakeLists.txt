cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ dht_test_src)
add_executable(dht_test ${dht_test_src})

add_dependencies(dht_test dht)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(dht_test PRIVATE dht transport security common protos gmssl gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(dht_test PRIVATE dht transport common protos gtest gtest_main gmock gmock_main)
endif()
