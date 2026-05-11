cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ websocket_test_src)
add_executable(websocket_test ${websocket_test_src})

# Same as lib websocket: WebSocket++ headers are not C++20-clean with current toolchain.
set_target_properties(websocket_test PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

add_dependencies(websocket_test websocket)
target_link_libraries(websocket_test PRIVATE websocket boost_system gtest gtest_main gmock gmock_main pthread dl)
