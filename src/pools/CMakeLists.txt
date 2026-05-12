cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ pools_src)
add_library(pools STATIC ${pools_src})

target_link_libraries(pools PRIVATE sync network security)
if (XENABLE_CODE_COVERAGE)
    target_link_libraries(pools PRIVATE gcov)
    # Enables ShardStatistic::Init synthetic tag + TxPoolManager::AddTx in headers for coverage runs only.
    target_compile_definitions(pools PRIVATE SETH_UNITTEST)
endif()
