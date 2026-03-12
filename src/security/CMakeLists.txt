cmake_minimum_required(VERSION 3.8)

set(WHITEBOX_PK "{0x00}" CACHE STRING "Whitebox Public Key")
set(WHITEBOX_SK "{0x00}" CACHE STRING "Whitebox Secret Key")

target_compile_definitions(seth_security PRIVATE
    REPLACE_WHITEBOX_PK=${WHITEBOX_PK}
    REPLACE_WHITEBOX_SK=${WHITEBOX_SK}
)

aux_source_directory(./ security_src)
aux_source_directory(./ecdsa ecdsa_src)
aux_source_directory(./gmssl gmssl_src)
aux_source_directory(./oqs oqs_src)
add_library(security STATIC ${oqs_src} ${gmssl_src} ${ecdsa_src} ${security_src} )

target_link_libraries(security PRIVATE common oqs ssl crypto secp256k1 ethash gmssl)
if (XENABLE_CODE_COVERAGE)
    target_link_libraries(security PRIVATE gcov)
endif()
