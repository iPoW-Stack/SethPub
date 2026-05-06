#pragma once

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>

#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>

#include <spdlog/spdlog.h>

#if defined(__has_include)
#if __has_include(<spdlog/fmt/bundled/printf.h>)
#include <spdlog/fmt/bundled/printf.h>
#elif __has_include(<fmt/printf.h>)
#include <fmt/printf.h>
#else
#error "Need spdlog bundled fmt or libfmt-dev (fmt/printf.h) for printf-style log macros."
#endif
#else
#include <spdlog/fmt/bundled/printf.h>
#endif

#ifdef _WIN32
#define SETH_LOG_FILE_NAME (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
#define SETH_LOG_FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

namespace seth::common {

void InitSpdlog(const char* log_dir = "./logs", const char* log_base_name = "seth.log");
void ShutdownSpdlog();

}  // namespace seth::common

#ifdef NDEBUG
#define DEBUG(fmt_str, ...)
#define SETH_DEBUG(fmt_str, ...)
#else
#define DEBUG(fmt_str, ...)                                                                          \
    spdlog::debug(                                                                                   \
        "[{}][{}][{}] {}", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, fmt::sprintf(fmt_str, ##__VA_ARGS__))
#define SETH_DEBUG(fmt_str, ...)                                                                     \
    spdlog::debug(                                                                                   \
        "[{}][{}][{}] {}", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, fmt::sprintf(fmt_str, ##__VA_ARGS__))
#endif

#define SETH_INFO(fmt_str, ...)                                                                    \
    spdlog::info(                                                                                    \
        "[{}][{}][{}] {}", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, fmt::sprintf(fmt_str, ##__VA_ARGS__))

#define SETH_WARN(fmt_str, ...)                                                                    \
    spdlog::warn(                                                                                    \
        "[{}][{}][{}] {}", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, fmt::sprintf(fmt_str, ##__VA_ARGS__))

#define SETH_ERROR(fmt_str, ...)                                                                   \
    spdlog::error(                                                                                   \
        "[{}][{}][{}] {}", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, fmt::sprintf(fmt_str, ##__VA_ARGS__))

#define SETH_FATAL(fmt_str, ...)                                                                   \
    do {                                                                                             \
        spdlog::critical(                                                                            \
            "[{}][{}][{}] {}", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__,                          \
            fmt::sprintf(fmt_str, ##__VA_ARGS__));                                                  \
        assert(false);                                                                               \
        std::abort();                                                                                \
    } while (0)

inline std::string ProtobufToJson(const google::protobuf::Message& message, bool pretty_print = false) {
#ifdef NDEBUG
    (void)message;
    (void)pretty_print;
    return "";
#else
    std::string json_str;
    google::protobuf::util::JsonPrintOptions options;
    options.add_whitespace = pretty_print;
    const auto status = google::protobuf::util::MessageToJsonString(message, &json_str, options);
    if (!status.ok()) {
        return "";
    }
    return json_str;
#endif
}
