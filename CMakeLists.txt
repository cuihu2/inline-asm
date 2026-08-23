cmake_minimum_required(VERSION 3.16)

project(inline_asm_codegen LANGUAGES CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(encode)

set(HPU_TEST_CONFIG
        "${CMAKE_CURRENT_SOURCE_DIR}/config/fhe_test.conf"
        CACHE FILEPATH
        "Shared HPU instruction/reference test configuration")

add_library(hpu_test_config STATIC
        src/config/fhe_test_config.cpp
)
target_include_directories(hpu_test_config
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(hpu_test_config
        PRIVATE
        HPU_DEFAULT_TEST_CONFIG_PATH="${HPU_TEST_CONFIG}"
)

add_executable(inline_asm_codegen
        src/main.cpp
        src/util/ntt.cpp
        src/util/mm.cpp
        src/util/bconv.cpp
        src/poly/auto.cpp
        src/poly/modup.cpp
        src/poly/moddown.cpp
        src/poly/pmult.cpp
        src/poly/cmult.cpp
        src/operator/keyswitch.cpp
        src/operator/relinearization.cpp
        src/operator/ciphertext_multiply.cpp
        src/operator/encode.cpp
        src/operator/rescale.cpp
)

target_include_directories(inline_asm_codegen
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(inline_asm_codegen PRIVATE hpu_test_config)

add_subdirectory(test/encode)
add_subdirectory(test/reference)

set(HPU_DELIVERY_TEST_DEPENDENCIES)
if(BUILD_TESTING)
    list(APPEND HPU_DELIVERY_TEST_DEPENDENCIES hpu_encode_self_test)
endif()

add_custom_target(hpu_delivery
        COMMAND $<TARGET_FILE:inline_asm_codegen>
                both
                --config ${HPU_TEST_CONFIG}
        COMMAND $<TARGET_FILE:inline_asm_encode_outputs>
        COMMAND $<TARGET_FILE:hpu_reference_vectors>
                ${CMAKE_CURRENT_SOURCE_DIR}/outputs/ciphertext_multiply/test_data
                ${CMAKE_CURRENT_SOURCE_DIR}/outputs
                --config ${HPU_TEST_CONFIG}
        COMMAND ${CMAKE_COMMAND}
                -DROOT=${CMAKE_CURRENT_SOURCE_DIR}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/test/delivery/check_delivery.cmake
        DEPENDS
        inline_asm_codegen
        inline_asm_encode_outputs
        hpu_reference_vectors
        ${HPU_DELIVERY_TEST_DEPENDENCIES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating HPU instruction streams and FHE reference deliverables"
)
