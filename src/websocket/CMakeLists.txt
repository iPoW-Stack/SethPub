cmake_minimum_required(VERSION 3.14)

# Optional: OFF for air‑gapped builds (install libwebsocketpp-dev or vendor under third_party).
option(P2P_FETCH_WEBSOCKETPP "Fetch websocketpp from GitHub if not found locally" ON)

# Boost (Asio) — websocketpp pulls boost/asio headers. Prefer CMake package if present,
# otherwise fall back to typical system prefixes (avoid hard REQUIRED for minimal images).
find_package(Boost QUIET COMPONENTS system thread atomic)

# Headers: .../<root>/websocketpp/common/thread.hpp
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
    if(NOT P2P_FETCH_WEBSOCKETPP)
        message(FATAL_ERROR
            "websocketpp not found (missing websocketpp/common/thread.hpp). "
            "Install libwebsocketpp-dev, clone under third_party/websocketpp, "
            "or configure with -DP2P_FETCH_WEBSOCKETPP=ON.")
    endif()
    include(FetchContent)
    message(STATUS "websocket: FetchContent downloading websocketpp 0.8.2...")
    FetchContent_Declare(
        deps_websocketpp
        URL https://github.com/zaphoyd/websocketpp/archive/refs/tags/0.8.2.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(deps_websocketpp)
    set(WEBSOCKETPP_INCLUDE_ROOT "${deps_websocketpp_SOURCE_DIR}")
endif()

if(NOT EXISTS "${WEBSOCKETPP_INCLUDE_ROOT}/websocketpp/common/thread.hpp")
    message(FATAL_ERROR
        "websocketpp layout invalid under: ${WEBSOCKETPP_INCLUDE_ROOT}")
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
