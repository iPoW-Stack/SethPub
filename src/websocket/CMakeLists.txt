cmake_minimum_required(VERSION 3.8)

# WebSocket++ headers: prefer third_party/include (same layout as global include path).
set(_WEBSOCKETPP_VENDOR_INCLUDE "${CMAKE_SOURCE_DIR}/third_party/include")
if(EXISTS "${_WEBSOCKETPP_VENDOR_INCLUDE}/websocketpp/common/thread.hpp")
    set(_WEBSOCKETPP_INCLUDE_DIR "${_WEBSOCKETPP_VENDOR_INCLUDE}")
else()
    include(FetchContent)
    # Pinned develop: Boost 1.87+ removed io_service / resolver::query; C++20 fixes destructor template-id.
    # Tag 0.8.2 no longer builds against current Boost.Asio.
    FetchContent_Declare(
        websocketpp
        GIT_REPOSITORY https://github.com/zaphoyd/websocketpp.git
        GIT_TAG bce258674b2d544f981da4bf149244a76e8126c9
    )
    FetchContent_GetProperties(websocketpp)
    if(NOT websocketpp_POPULATED)
        FetchContent_Populate(websocketpp)
    endif()
    set(_WEBSOCKETPP_INCLUDE_DIR "${websocketpp_SOURCE_DIR}")
endif()

aux_source_directory(./ websocket_src)
add_library(websocket ${websocket_src} "websocket_client.h")

target_include_directories(websocket PUBLIC "${_WEBSOCKETPP_INCLUDE_DIR}")
target_link_libraries(websocket PRIVATE common boost_system boost_thread boost_atomic ssl crypto pthread dl)
