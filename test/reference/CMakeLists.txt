add_executable(hpu_reference_vectors
        main.cpp
)
target_link_libraries(hpu_reference_vectors
        PRIVATE
        hpu_test_config
        hpu_hardware_model
        hpu_scheme_encoding
)

if(BUILD_TESTING AND HPU_ENABLE_LEGACY_FIXED_PROFILE_TESTS)
    add_test(
            NAME hpu_reference_vectors_self_test
            COMMAND hpu_reference_vectors
                    ${CMAKE_CURRENT_BINARY_DIR}/reference_test_data
                    --config ${HPU_TEST_CONFIG}
    )
    set_tests_properties(
            hpu_reference_vectors_self_test
            PROPERTIES
            TIMEOUT 120
            LABELS "legacy-fixed-profile")
endif()
