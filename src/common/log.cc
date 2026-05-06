#include "common/log.h"

#include <cerrno>
#include <cstring>
#include <string>

#include <spdlog/async.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>

#ifdef _WIN32
#include <direct.h>
#include <errno.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

namespace seth::common {

namespace {

void EnsureLogDir(const char* log_dir) {
#ifdef _WIN32
    if (_mkdir(log_dir) != 0 && errno != EEXIST) {
        return;
    }
#else
    if (mkdir(log_dir, 0755) != 0 && errno != EEXIST) {
        return;
    }
#endif
}

}  // namespace

void InitSpdlog(const char* log_dir, const char* log_base_name) {
    EnsureLogDir(log_dir);
    const std::string path = std::string(log_dir) + "/" + log_base_name;

    constexpr std::size_t kMaxFileBytes = 10 * 1024 * 1024;
    constexpr int kMaxRotatedFiles = 4;

    spdlog::init_thread_pool(8192, 1);
    auto logger = spdlog::create_async<spdlog::sinks::rotating_file_sink_mt>(
        "seth", path, kMaxFileBytes, kMaxRotatedFiles);
    spdlog::set_default_logger(logger);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    spdlog::flush_on(spdlog::level::warn);
}

void ShutdownSpdlog() {
    spdlog::shutdown();
}

}  // namespace seth::common
