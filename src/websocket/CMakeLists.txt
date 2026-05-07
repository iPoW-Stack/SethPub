cmake_minimum_required(VERSION 3.8)

find_package(Boost REQUIRED COMPONENTS system thread atomic)

# Headers live either at repo root (.../websocketpp/common/...) or under include/
find_path(WEBSOCKETPP_INCLUDE_ROOT
    NAMES websocketpp/common/thread.hpp
    PATHS
        "${CMAKE_SOURCE_DIR}/third_party"
        "${CMAKE_SOURCE_DIR}/third_party/websocketpp"
        "$ENV{WEBSOCKETPP_ROOT}"
        /usr/include
        /usr/local/include
)

if(NOT WEBSOCKETPP_INCLUDE_ROOT)
    message(FATAL_ERROR
        "websocketpp not found (missing websocketpp/common/thread.hpp). "
        "Install distro package (e.g. libwebsocketpp-dev) or clone "
        "https://github.com/zaphoyd/websocketpp under third_party/websocketpp.")
endif()

aux_source_directory(./ websocket_src)
add_library(websocket ${websocket_src} "websocket_client.h")

target_include_directories(websocket BEFORE PRIVATE
    "${WEBSOCKETPP_INCLUDE_ROOT}"
    "${Boost_INCLUDE_DIRS}")

target_link_libraries(websocket PRIVATE common boost_system boost_thread boost_atomic ssl crypto pthread dl)
