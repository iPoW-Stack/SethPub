cmake_minimum_required(VERSION 3.22)

aux_source_directory(./ sethvm_src)
add_library(sethvm STATIC ${sethvm_src})

target_link_libraries(sethvm PRIVATE contract common evmone evmc-loader evmc-instructions)
if (XENABLE_CODE_COVERAGE)
    target_link_libraries(sethvm PRIVATE gcov)
endif()

