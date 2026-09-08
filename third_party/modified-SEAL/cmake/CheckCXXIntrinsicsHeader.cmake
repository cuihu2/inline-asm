# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check for intrinsics header files.
if(SEAL_USE_INTRIN)
    set(CMAKE_REQUIRED_QUIET_OLD ${CMAKE_REQUIRED_QUIET})
    set(CMAKE_REQUIRED_QUIET ON)

    if(MSVC)
        # For MSVC, all the intrinsics we need are in intrin.h.
        set(SEAL_INTRIN_HEADER "intrin.h")
    else()
        # A few intrinsics are Intel-only; we expect these to be in x86intrin.h.
        set(SEAL_INTRIN_HEADER "x86intrin.h")
    endif()

    # Check if the intrinsics header file exists. Otherwise, unset the variable.
    check_include_file_cxx(${SEAL_INTRIN_HEADER} SEAL_INTRIN_HEADER_FOUND)
    set(CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET_OLD})

    if(SEAL_INTRIN_HEADER_FOUND)
        message(STATUS "${SEAL_INTRIN_HEADER} - found")
    else()
        unset(SEAL_INTRIN_HEADER)
    endif()
endif()
