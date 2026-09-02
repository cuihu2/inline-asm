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

option(HPU_ENABLE_SEAL_DIFFERENTIAL_ORACLE
        "Build the optional BFV/BGV/CKKS differential oracle against SEAL"
        OFF)
option(HPU_ENABLE_SEAL_BFV_ORACLE
        "Deprecated alias for HPU_ENABLE_SEAL_DIFFERENTIAL_ORACLE"
        OFF)
set(HPU_SEAL_SOURCE_DIR
        "/home/songyexin/fhe/SEAL"
        CACHE PATH
        "Modified SEAL source tree used only by the optional differential oracle")

if(HPU_ENABLE_SEAL_BFV_ORACLE)
    message(DEPRECATION
        "HPU_ENABLE_SEAL_BFV_ORACLE is deprecated; use "
        "HPU_ENABLE_SEAL_DIFFERENTIAL_ORACLE instead")
    set(HPU_ENABLE_SEAL_DIFFERENTIAL_ORACLE ON CACHE BOOL "" FORCE)
endif()

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
        src/scheme/detail/integer_encode.cpp
        src/scheme/ckks/encode.cpp
        src/scheme/bgv/encode.cpp
        src/scheme/bfv/encode.cpp
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
        src/operator/rounded_drop_last.cpp
        src/scheme/ckks/rescale.cpp
        src/scheme/ckks/ciphertext_multiply.cpp
        src/scheme/bgv/ciphertext_multiply.cpp
        src/scheme/bgv/modswitch.cpp
        src/scheme/bfv/ciphertext_multiply.cpp
        src/scheme/bfv/modswitch.cpp
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
            invalid_composite_plaintext_modulus
            invalid_bfv_num_b)
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

if(HPU_ENABLE_SEAL_DIFFERENTIAL_ORACLE)
    if(NOT EXISTS "${HPU_SEAL_SOURCE_DIR}/CMakeLists.txt")
        message(FATAL_ERROR
            "HPU_ENABLE_SEAL_DIFFERENTIAL_ORACLE requires a SEAL source tree at ${HPU_SEAL_SOURCE_DIR}")
    endif()
    set(SEAL_EXPERIMENTAL_BFV_NO_SMRQ ON CACHE BOOL "" FORCE)
    set(SEAL_EXPERIMENTAL_BFV_BRANCHLESS_SK ON CACHE BOOL "" FORCE)
    set(SEAL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_BENCH OFF CACHE BOOL "" FORCE)
    set(SEAL_BUILD_DEPS ON CACHE BOOL "" FORCE)
    set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
    add_subdirectory(
        "${HPU_SEAL_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}/seal_differential_oracle"
        EXCLUDE_FROM_ALL)

    execute_process(
        COMMAND git -C "${HPU_SEAL_SOURCE_DIR}" rev-parse HEAD
        OUTPUT_VARIABLE HPU_SEAL_GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE HPU_SEAL_GIT_RESULT)
    if(NOT HPU_SEAL_GIT_RESULT EQUAL 0)
        set(HPU_SEAL_GIT_COMMIT "unknown")
    endif()
    execute_process(
        COMMAND git -C "${HPU_SEAL_SOURCE_DIR}" status --porcelain
        OUTPUT_VARIABLE HPU_SEAL_GIT_STATUS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(HPU_SEAL_GIT_STATUS STREQUAL "")
        set(HPU_SEAL_WORKTREE_STATE "CLEAN")
    else()
        set(HPU_SEAL_WORKTREE_STATE "DIRTY")
    endif()
    file(SHA256 "${HPU_SEAL_SOURCE_DIR}/CMakeLists.txt" HPU_SEAL_CMAKE_SHA256)
    file(SHA256 "${HPU_SEAL_SOURCE_DIR}/native/src/seal/evaluator.cpp"
        HPU_SEAL_EVALUATOR_SHA256)
    file(SHA256 "${HPU_SEAL_SOURCE_DIR}/native/src/seal/util/rns.cpp"
        HPU_SEAL_RNS_CPP_SHA256)
    file(SHA256 "${HPU_SEAL_SOURCE_DIR}/native/src/seal/util/rns.h"
        HPU_SEAL_RNS_HPP_SHA256)

    add_executable(
        hpu_seal_differential_test
        test/seal_differential_oracle.cpp)
    target_link_libraries(hpu_seal_differential_test PRIVATE SEAL::seal)
    target_compile_definitions(hpu_seal_differential_test PRIVATE
        HPU_SEAL_GIT_COMMIT="${HPU_SEAL_GIT_COMMIT}"
        HPU_SEAL_WORKTREE_STATE="${HPU_SEAL_WORKTREE_STATE}"
        HPU_SEAL_CMAKE_SHA256="${HPU_SEAL_CMAKE_SHA256}"
        HPU_SEAL_EVALUATOR_SHA256="${HPU_SEAL_EVALUATOR_SHA256}"
        HPU_SEAL_RNS_CPP_SHA256="${HPU_SEAL_RNS_CPP_SHA256}"
        HPU_SEAL_RNS_HPP_SHA256="${HPU_SEAL_RNS_HPP_SHA256}")
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
    add_test(
            NAME hpu_reference_rejects_insufficient_bfv_b_range
            COMMAND hpu_reference_vectors
                    ${CMAKE_CURRENT_BINARY_DIR}/insufficient_bfv_b_range_test_data
                    --config ${CMAKE_CURRENT_SOURCE_DIR}/test/config/invalid_bfv_b_range.conf
    )
    set_tests_properties(
            hpu_reference_rejects_insufficient_bfv_b_range
            PROPERTIES WILL_FAIL TRUE TIMEOUT 120)
endif()

set(HPU_DELIVERY_TEST_DEPENDENCIES)
if(BUILD_TESTING)
    list(APPEND HPU_DELIVERY_TEST_DEPENDENCIES
        hpu_encode_self_test
        hpu_scheme_encode_self_test)
endif()

add_custom_target(hpu_delivery
        COMMAND $<TARGET_FILE:inline_asm_codegen>
                both
                --config ${HPU_TEST_CONFIG}
        COMMAND $<TARGET_FILE:inline_asm_encode_outputs>
                --config ${HPU_TEST_CONFIG}
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

if(HPU_ENABLE_SEAL_DIFFERENTIAL_ORACLE)
    add_custom_target(hpu_delivery_with_seal
        COMMAND $<TARGET_FILE:hpu_seal_differential_test>
                --outputs-root ${CMAKE_CURRENT_SOURCE_DIR}/outputs
                --report-dir ${CMAKE_CURRENT_BINARY_DIR}/seal_oracle
        DEPENDS
        hpu_delivery
        hpu_seal_differential_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Running HPU delivery checks and the SEAL three-scheme oracle"
    )

    if(BUILD_TESTING)
        add_test(
            NAME hpu_seal_oracle_prepare_delivery
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_CURRENT_BINARY_DIR}
                    --target hpu_delivery)
        set_tests_properties(hpu_seal_oracle_prepare_delivery PROPERTIES
            FIXTURES_SETUP HPU_SEAL_ORACLE_FIXTURE
            RUN_SERIAL TRUE
            TIMEOUT 300)

        add_test(
            NAME hpu_seal_differential_oracle
            COMMAND hpu_seal_differential_test
                    --outputs-root ${CMAKE_CURRENT_SOURCE_DIR}/outputs
                    --report-dir ${CMAKE_CURRENT_BINARY_DIR}/seal_oracle)
        set_tests_properties(hpu_seal_differential_oracle PROPERTIES
            FIXTURES_REQUIRED HPU_SEAL_ORACLE_FIXTURE
            RUN_SERIAL TRUE
            TIMEOUT 300)

        add_test(
            NAME hpu_seal_oracle_rejects_corrupted_fixture
            COMMAND ${CMAKE_COMMAND}
                    -DORACLE=$<TARGET_FILE:hpu_seal_differential_test>
                    -DSOURCE_OUTPUTS=${CMAKE_CURRENT_SOURCE_DIR}/outputs
                    -DWORK_ROOT=${CMAKE_CURRENT_BINARY_DIR}/seal_oracle_corruption
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/test/seal_oracle_corruption_test.cmake)
        set_tests_properties(hpu_seal_oracle_rejects_corrupted_fixture PROPERTIES
            FIXTURES_REQUIRED HPU_SEAL_ORACLE_FIXTURE
            RUN_SERIAL TRUE
            TIMEOUT 300)
    endif()
endif()
