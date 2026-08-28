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

add_library(hpu_scheme_encoding STATIC
        src/util/ntt.cpp
        src/operator/plaintext_ntt.cpp
        src/scheme/ckks/encode.cpp
        src/scheme/bgv/encode.cpp
)
target_include_directories(hpu_scheme_encoding
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(inline_asm_codegen
        src/main.cpp
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
        src/scheme/ckks/rescale.cpp
        src/scheme/ckks/ciphertext_multiply.cpp
        src/scheme/bgv/ciphertext_multiply.cpp
        src/scheme/bgv/modswitch.cpp
)

target_include_directories(inline_asm_codegen
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(inline_asm_codegen
        PRIVATE
        hpu_test_config
        hpu_scheme_encoding
)

if(BUILD_TESTING)
    foreach(INVALID_CONFIG
            invalid_context_overflow
            invalid_num_q
            invalid_plaintext_modulus
            invalid_bgv_batching_modulus
            invalid_composite_plaintext_modulus)
        add_test(
                NAME hpu_config_rejects_${INVALID_CONFIG}
                COMMAND inline_asm_codegen
                        asm
                        --config ${CMAKE_CURRENT_SOURCE_DIR}/test/config/${INVALID_CONFIG}.conf
        )
        set_tests_properties(
                hpu_config_rejects_${INVALID_CONFIG}
                PROPERTIES WILL_FAIL TRUE)
    endforeach()

    add_executable(hpu_scheme_encode_self_test
            test/scheme_encode_self_test.cpp
    )
    target_link_libraries(hpu_scheme_encode_self_test
            PRIVATE
            hpu_scheme_encoding
    )
    add_test(NAME hpu_scheme_encode_self_test COMMAND hpu_scheme_encode_self_test)
endif()

add_subdirectory(test/encode)
add_subdirectory(test/reference)

if(BUILD_TESTING)
    add_test(
            NAME hpu_reference_rejects_noninvertible_plaintext_modulus
            COMMAND hpu_reference_vectors
                    ${CMAKE_CURRENT_BINARY_DIR}/noninvertible_reference_test_data
                    --config ${CMAKE_CURRENT_SOURCE_DIR}/test/config/noninvertible_plaintext_modulus.conf
    )
    set_tests_properties(
            hpu_reference_rejects_noninvertible_plaintext_modulus
            PROPERTIES WILL_FAIL TRUE TIMEOUT 120)
endif()

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
