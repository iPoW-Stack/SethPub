cmake_minimum_required(VERSION 3.8)

# Boost (Asio) — websocketpp pulls boost/asio headers. Prefer CMake package if present,
# otherwise fall back to typical system prefixes (avoid hard REQUIRED for minimal images).
find_package(Boost QUIET COMPONENTS system thread atomic)

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
    "${WEBSOCKETPP_INCLUDE_ROOT}")

if(Boost_FOUND)
    target_include_directories(websocket BEFORE PRIVATE "${Boost_INCLUDE_DIRS}")
elseif(EXISTS "/usr/include/boost/version.hpp")
    target_include_directories(websocket BEFORE PRIVATE "/usr/include")
elseif(EXISTS "/usr/local/include/boost/version.hpp")
    target_include_directories(websocket BEFORE PRIVATE "/usr/local/include")
endif()

target_link_libraries(websocket PRIVATE common boost_system boost_thread boost_atomic ssl crypto pthread dl)
