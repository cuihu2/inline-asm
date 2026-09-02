if(NOT DEFINED ORACLE OR NOT EXISTS "${ORACLE}")
    message(FATAL_ERROR "ORACLE executable is missing")
endif()
if(NOT DEFINED SOURCE_OUTPUTS OR NOT EXISTS "${SOURCE_OUTPUTS}/seal_oracle/parameters.csv")
    message(FATAL_ERROR "generated SEAL oracle fixtures are missing")
endif()
if(NOT DEFINED WORK_ROOT)
    message(FATAL_ERROR "WORK_ROOT is required")
endif()

file(REMOVE_RECURSE "${WORK_ROOT}")
file(MAKE_DIRECTORY "${WORK_ROOT}/outputs")
file(COPY "${SOURCE_OUTPUTS}/seal_oracle"
     DESTINATION "${WORK_ROOT}/outputs")

foreach(CASE_NAME
        bfv_encode
        bfv_ciphertext_multiply
        bgv_encode
        bgv_ciphertext_multiply
        ckks_encode
        ckks_ciphertext_multiply)
    file(MAKE_DIRECTORY "${WORK_ROOT}/outputs/${CASE_NAME}/test_data")
    file(COPY "${SOURCE_OUTPUTS}/${CASE_NAME}/test_data/host"
         DESTINATION "${WORK_ROOT}/outputs/${CASE_NAME}/test_data")
endforeach()

set(CORRUPTED_FILE
    "${WORK_ROOT}/outputs/bfv_encode/test_data/host/batch_coefficients_mod_t.csv")
file(READ "${CORRUPTED_FILE}" CONTENTS)
string(REGEX MATCH "\n([0-9]+),([0-9]+)\n" FIRST_DATA_FIELD "${CONTENTS}")
if(FIRST_DATA_FIELD STREQUAL "")
    message(FATAL_ERROR "unable to locate BFV coefficient to corrupt")
endif()
set(FIRST_INDEX "${CMAKE_MATCH_1}")
set(ORIGINAL_VALUE "${CMAKE_MATCH_2}")
math(EXPR CORRUPTED_VALUE "${ORIGINAL_VALUE} + 1")
string(REPLACE
    "${FIRST_DATA_FIELD}"
    "\n${FIRST_INDEX},${CORRUPTED_VALUE}\n"
    CONTENTS "${CONTENTS}")
file(WRITE "${CORRUPTED_FILE}" "${CONTENTS}")

execute_process(
    COMMAND "${ORACLE}"
            --outputs-root "${WORK_ROOT}/outputs"
            --report-dir "${WORK_ROOT}/report"
    RESULT_VARIABLE ORACLE_RESULT
    OUTPUT_VARIABLE ORACLE_STDOUT
    ERROR_VARIABLE ORACLE_STDERR)
if(ORACLE_RESULT EQUAL 0)
    message(FATAL_ERROR "SEAL oracle accepted a corrupted BFV coefficient fixture")
endif()
if(NOT ORACLE_STDERR MATCHES "BFV batch_encode_coefficients")
    message(FATAL_ERROR
        "SEAL oracle failed for an unexpected reason: ${ORACLE_STDERR}")
endif()
if(NOT EXISTS "${WORK_ROOT}/report/report.csv")
    message(FATAL_ERROR "failed oracle did not write report.csv")
endif()

message(STATUS "SEAL oracle rejected the isolated corrupted fixture as expected")
