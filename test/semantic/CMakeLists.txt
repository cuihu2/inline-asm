add_test(
        NAME hpu_semantic_self_test
        COMMAND ${Python3_EXECUTABLE}
                -B
                -m unittest discover
                -s ${CMAKE_CURRENT_SOURCE_DIR}
                -p test_*.py
)
set_tests_properties(
        hpu_semantic_self_test
        PROPERTIES
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1"
        TIMEOUT 180)
