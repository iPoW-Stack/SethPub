#include <iostream>
#include <queue>
#include <vector>

#include "init/network_init.h"

static void GlobalInitSpdlog() {
    spdlog::init_thread_pool(8192, 1);

    // auto logger = spdlog::create_async<spdlog::sinks::basic_file_sink_mt>(
    //     "async_file", "log/seth.log", false);
    auto logger = spdlog::basic_logger_mt("sync_file", "log/seth.log", false);
    spdlog::set_default_logger(logger);
    spdlog::set_pattern("%Y-%m-%d %H:%M:%S.%e [thread %t] %-5l [%n] %v%$");
    for (auto& sink : logger->sinks()) {
        sink->set_pattern("%Y-%m-%d %H:%M:%S.%e [thread %t] %-5l [%n] %v%$");
    }

    spdlog::set_level(spdlog::level::debug);
    spdlog::flush_on(spdlog::level::err);
    spdlog::debug("init spdlog success: %d", 1);
}

int main(int argc, char** argv) {
    GlobalInitSpdlog();
    seth::common::SignalRegister();
    seth::init::NetworkInit init;
    if (init.Init(argc, argv) != 0) {
        SETH_ERROR("init network error!");
        return 1;
    }

    init.Destroy();
    return 0;
}
