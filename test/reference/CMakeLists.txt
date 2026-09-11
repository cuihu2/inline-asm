add_executable(hpu_reference_vectors
        main.cpp
)
target_link_libraries(hpu_reference_vectors
        PRIVATE
        hpu_test_config
        hpu_scheme_encoding
)

add_executable(hpu_ntt_hardware_model_test
        ntt_hardware_model_test.cpp
)
target_compile_definitions(hpu_ntt_hardware_model_test PRIVATE
        HPU_NTT_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/ntt_hw_ut"
)

if(BUILD_TESTING)
    add_test(
            NAME hpu_reference_vectors_self_test
            COMMAND hpu_reference_vectors
                    ${CMAKE_CURRENT_BINARY_DIR}/reference_test_data
                    --config ${HPU_TEST_CONFIG}
    )
    set_tests_properties(hpu_reference_vectors_self_test PROPERTIES TIMEOUT 120)

    add_test(
            NAME hpu_ntt_hardware_model_test
            COMMAND hpu_ntt_hardware_model_test
    )

    add_test(
            NAME hpu_reference_vectors_general_auto
            COMMAND hpu_reference_vectors
                    ${CMAKE_CURRENT_BINARY_DIR}/reference_auto_galois_9_test_data
                    --config ${CMAKE_CURRENT_SOURCE_DIR}/../config/valid_auto_galois_9.conf
    )
    set_tests_properties(
            hpu_reference_vectors_general_auto
            PROPERTIES TIMEOUT 120)
endif()
