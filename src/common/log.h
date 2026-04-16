#pragma once

#include <string.h>

// #include "log4cpp/Category.hh"
// #include "log4cpp/Appender.hh"
// #include "log4cpp/FileAppender.hh"
// #include "log4cpp/OstreamAppender.hh"
// #include "log4cpp/Layout.hh"
// #include "log4cpp/BasicLayout.hh"
// #include "log4cpp/Priority.hh"
// #include "log4cpp/PropertyConfigurator.hh"
#include <google/protobuf/util/json_util.h>
#include <spdlog/fmt/bundled/printf.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/async.h"


#define SETH_DEBUG(logfmt, ...)
#ifdef _WIN32
#define SETH_LOG_FILE_NAME strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__
#else
#define SETH_LOG_FILE_NAME strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__
#endif

#ifdef _WIN32

#ifdef NDEBUG
#define DEBUG(logfmt, ...)
#define SETH_DEBUG(logfmt, ...)
#else
// #define DEBUG(logfmt, ...)
// #define SETH_DEBUG(logfmt, ...)

#define DEBUG(logfmt, ...)  do {\
    SafeLog(spdlog::level::debug, fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)
// #define SETH_DEBUG(logfmt, ...)
#define SETH_DEBUG(logfmt, ...)  do {\
    SafeLog(spdlog::level::debug, fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)
#endif

#define SETH_INFO(logfmt, ...)  do {\
    SafeLog(spdlog::level::info, fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)

#define SETH_WARN(logfmt, ...)  do {\
    SafeLog(spdlog::level::warn, fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)

#define SETH_ERROR(logfmt, ...)  do {\
    SafeLog(spdlog::level::err, fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)

#define SETH_FATAL(logfmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " logfmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
    SafeLog(spdlog::level::critical, fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
    assert(false);\
    exit(0);\
} while (0)
#else

#ifdef NDEBUG
#define DEBUG(logfmt, ...)
#define SETH_DEBUG(logfmt, ...)
#else
//#define DEBUG(logfmt, ...)
//#define SETH_DEBUG(logfmt, ...)
#define DEBUG(logfmt, ...)  do {\
    SafeLog(spdlog::level::debug, fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)
#define SETH_DEBUG(logfmt, ...)  do {\
    spdlog::debug(fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)
#endif
// #define SETH_INFO(logfmt, ...)
// #define SETH_WARN(logfmt, ...)
#define SETH_INFO(logfmt, ...)  do {\
    spdlog::info(fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)

#define SETH_WARN(logfmt, ...)  do {\
    spdlog::warn(fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)

#define SETH_ERROR(logfmt, ...)  do {\
    spdlog::error(fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
} while (0)

#define SETH_FATAL(logfmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " logfmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
    spdlog::critical(fmt::sprintf("[%s][%s][%d] " logfmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__));\
    assert(false);\
    exit(0);\
} while (0)

#endif // _WIN32

// Safe logging helpers: guard against spdlog being uninitialized or shutdown
static inline void SafeLog(spdlog::level::level_enum lvl, const std::string &msg) {
    auto logger = spdlog::default_logger_raw();
    if (logger) {
        logger->log(lvl, msg);
    } else {
        // fallback to stderr to avoid crashing during shutdown/init races
        fprintf(stderr, "%s\n", msg.c_str());
    }
}


// #ifdef LOG
// #undef LOG
// #endif // LOG
// #define LOG(level) LOG_INS << level << "[" << SETH_LOG_FILE_NAME << ": " << __LINE__ << "]"

#ifdef FOR_CONSOLE_DEBUG
#undef DEBUG
#undef SETH_INFO
#undef SETH_WARN
#undef SETH_ERROR

#ifdef NDEBUG
#define DEBUG(logfmt, ...)
#define SETH_DEBUG(logfmt, ...)
#else
 #define DEBUG(logfmt, ...)
 #define SETH_DEBUG(logfmt, ...)
/*
#define DEBUG(logfmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#define SETH_DEBUG(logfmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
*/
#endif

#define SETH_INFO(logfmt, ...)  do {\
    printf("[INFO][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_WARN(logfmt, ...)  do {\
    printf("[WARN][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_ERROR(logfmt, ...)  do {\
    printf("[ERROR][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_FATAL(logfmt, ...)  do {\
    printf("[FATAL][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
    assert(false);\
    exit(0);\
} while (0)

#endif

static inline std::string ProtobufToJson(const google::protobuf::Message& message, bool pretty_print = false) {
#ifdef NDEBUG
    return "";
#endif
    std::string json_str;
    google::protobuf::util::JsonPrintOptions options;
    options.add_whitespace = pretty_print;
    auto status = google::protobuf::util::MessageToJsonString(message, &json_str, options);
    if (!status.ok()) {
        return "";
    }
    return json_str;
}
