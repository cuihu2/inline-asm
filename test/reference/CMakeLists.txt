add_executable(hpu_reference_vectors
        main.cpp
)
target_link_libraries(hpu_reference_vectors
        PRIVATE
        hpu_test_config
        hpu_scheme_encoding
)

if(BUILD_TESTING)
    add_test(
            NAME hpu_reference_vectors_self_test
            COMMAND hpu_reference_vectors
                    ${CMAKE_CURRENT_BINARY_DIR}/reference_test_data
                    --config ${HPU_TEST_CONFIG}
    )
    set_tests_properties(hpu_reference_vectors_self_test PROPERTIES TIMEOUT 120)
endif()
