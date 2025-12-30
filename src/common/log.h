#pragma once

#include <string.h>

#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/PropertyConfigurator.hh"
#include <google/protobuf/util/json_util.h>


#define SETH_DEBUG(fmt, ...)
#ifdef _WIN32
#define SETH_LOG_FILE_NAME strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__
#else
#define SETH_LOG_FILE_NAME strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__
#endif

#define LOG_INS log4cpp::Category::getInstance(std::string("sub1"))
#ifdef _WIN32

#ifdef NDEBUG
#define DEBUG(fmt, ...)
#define SETH_DEBUG(fmt, ...)
#else
// #define DEBUG(fmt, ...)
// #define SETH_DEBUG(fmt, ...)

#define DEBUG(fmt, ...)  do {\
    LOG_INS.debug("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
// #define SETH_DEBUG(fmt, ...)
#define SETH_DEBUG(fmt, ...)  do {\
    LOG_INS.debug("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#endif

#define SETH_INFO(fmt, ...)  do {\
    LOG_INS.info("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_WARN(fmt, ...)  do {\
    LOG_INS.warn("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_ERROR(fmt, ...)  do {\
    LOG_INS.error("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_FATAL(fmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
    LOG_INS.fatal("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
    assert(false);\
    exit(0);\
} while (0)
#else

#ifdef NDEBUG
#define DEBUG(fmt, ...)
#define SETH_DEBUG(fmt, ...)
#else
// #define DEBUG(fmt, ...)
// #define SETH_DEBUG(fmt, ...)
#define DEBUG(fmt, ...)  do {\
    LOG_INS.debug("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#define SETH_DEBUG(fmt, ...)  do {\
    LOG_INS.debug("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#endif
// #define SETH_INFO(fmt, ...)
// #define SETH_WARN(fmt, ...)
#define SETH_INFO(fmt, ...)  do {\
    LOG_INS.info("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_WARN(fmt, ...)  do {\
    LOG_INS.warn("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_ERROR(fmt, ...)  do {\
    LOG_INS.error("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_FATAL(fmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
    LOG_INS.fatal("[%s][%s][%d] " fmt, SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
    assert(false);\
    exit(0);\
} while (0)

#endif // _WIN32

#ifdef LOG
#undef LOG
#endif // LOG
#define LOG(level) LOG_INS << level << "[" << SETH_LOG_FILE_NAME << ": " << __LINE__ << "]" 

#ifdef FOR_CONSOLE_DEBUG
#undef DEBUG
#undef SETH_INFO
#undef SETH_WARN
#undef SETH_ERROR

#ifdef NDEBUG
#define DEBUG(fmt, ...)
#define SETH_DEBUG(fmt, ...)
#else
 #define DEBUG(fmt, ...)
 #define SETH_DEBUG(fmt, ...)
/*
#define DEBUG(fmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#define SETH_DEBUG(fmt, ...)  do {\
    printf("[DEBUG][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
*/
#endif

#define SETH_INFO(fmt, ...)  do {\
    printf("[INFO][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_WARN(fmt, ...)  do {\
    printf("[WARN][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_ERROR(fmt, ...)  do {\
    printf("[ERROR][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define SETH_FATAL(fmt, ...)  do {\
    printf("[FATAL][%s][%s][%d] " fmt "\n", SETH_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
    assert(false);\
    exit(0);\
} while (0)

#endif

static std::string ProtobufToJson(const google::protobuf::Message& message, bool pretty_print = false) {
    // return "";
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
