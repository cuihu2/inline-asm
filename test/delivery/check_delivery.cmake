if(NOT DEFINED ROOT)
    message(FATAL_ERROR "ROOT is required")
endif()

set(REQUIRED_FILES
    "output/ciphertext_multiply.asm"
    "output/relinearization.asm"
    "outputs/relinearization/relinearization.inst32"
    "outputs/relinearization/relinearization.cmd26"
    "outputs/relinearization/test_data/expected_q.bin"
    "outputs/ciphertext_multiply/ciphertext_multiply.inst32"
    "outputs/ciphertext_multiply/ciphertext_multiply.cmd26"
    "outputs/ciphertext_multiply/test_data/params.json"
    "outputs/ciphertext_multiply/test_data/artifact_manifest.csv"
    "outputs/ciphertext_multiply/test_data/input/ct_a_q.bin"
    "outputs/ciphertext_multiply/test_data/input/ct_a_q.hex.txt"
    "outputs/ciphertext_multiply/test_data/input/ct_b_q.bin"
    "outputs/ciphertext_multiply/test_data/constants/relinearization_key_ntt_qp.bin"
    "outputs/ciphertext_multiply/test_data/expected/tensor_coeff_q.bin"
    "outputs/ciphertext_multiply/test_data/expected/keyswitch_moddown_q.bin"
    "outputs/ciphertext_multiply/test_data/expected/ciphertext_out_q.bin"
    "outputs/ciphertext_multiply/test_data/expected/plaintext_product_mod_t.bin"
    "outputs/ciphertext_multiply/test_data/VALIDATION.txt"
    "outputs/modup/test_data/input_digit_q.bin"
    "outputs/modup/test_data/expected_qp.bin"
    "outputs/ciphertext_multiply/test_data/hardware/abi.json"
    "outputs/ciphertext_multiply/test_data/hardware/hardware_manifest.csv"
    "outputs/ciphertext_multiply/test_data/hardware/hpu_mem_image.u32.bin"
    "outputs/ciphertext_multiply/test_data/hardware/hpu_mem_config.json"
    "outputs/ciphertext_multiply/test_data/hardware/line_map.csv"
    "outputs/ciphertext_multiply/test_data/hardware/mod_ctx_map.csv"
    "outputs/ciphertext_multiply/test_data/hardware/constants/mod_ctx.u32.bin"
    "outputs/ciphertext_multiply/test_data/hardware/twiddle_map.csv"
    "outputs/ciphertext_multiply/test_data/hardware/constants/twiddle/ntt/basis_00/stage_11.u32.bin"
    "outputs/ciphertext_multiply/test_data/hardware/constants/twiddle/intt/basis_00/stage_11.u32.bin"
    "outputs/rv_interface_smoke/rv_interface_smoke.asm"
    "outputs/rv_interface_smoke/rv_interface_smoke.inst32"
    "outputs/rv_interface_smoke/rv_interface_smoke.cmd26"
    "outputs/rv_interface_smoke/test_data/expected_decode.csv"
    "outputs/rv_interface_smoke/test_data/expected_cmd26.csv"
    "outputs/rv_interface_smoke/test_data/negative_cases.asm.txt"
    "outputs/intt/test_data/input.hex.txt"
    "outputs/intt/test_data/expected.hex.txt"
    "outputs/encode/test_data/input_coeff_q.bin"
    "outputs/encode/test_data/expected_ntt_q.bin"
    "outputs/rescale/test_data/input_q.bin"
    "outputs/rescale/test_data/constants/q_last_half_mod_q.bin"
    "outputs/rescale/test_data/constants/q_last_inv_mod_qprime.bin"
    "outputs/rescale/test_data/expected_qprime.bin"
)

foreach(CASE_NAME ntt intt encode rescale mm bconv modup pmult cmult moddown keyswitch relinearization)
    list(APPEND REQUIRED_FILES
        "outputs/${CASE_NAME}/test_data/params.json"
        "outputs/${CASE_NAME}/test_data/artifact_manifest.csv"
        "outputs/${CASE_NAME}/test_data/hardware/abi.json"
        "outputs/${CASE_NAME}/test_data/hardware/hpu_mem_image.u32.bin"
        "outputs/${CASE_NAME}/test_data/hardware/hpu_mem_config.json"
        "outputs/${CASE_NAME}/test_data/hardware/line_map.csv"
        "outputs/${CASE_NAME}/test_data/hardware/mod_ctx_map.csv"
        "outputs/${CASE_NAME}/test_data/hardware/twiddle_map.csv"
        "outputs/${CASE_NAME}/${CASE_NAME}.cmd26")
endforeach()
list(APPEND REQUIRED_FILES "outputs/auto/test_data/STATUS.md")

foreach(RELATIVE_PATH IN LISTS REQUIRED_FILES)
    set(PATH "${ROOT}/${RELATIVE_PATH}")
    if(NOT EXISTS "${PATH}")
        message(FATAL_ERROR "Missing delivery artifact: ${RELATIVE_PATH}")
    endif()
    file(SIZE "${PATH}" SIZE)
    if(SIZE EQUAL 0)
        message(FATAL_ERROR "Empty delivery artifact: ${RELATIVE_PATH}")
    endif()
endforeach()

# Executable custom1 streams use the frozen CPU/HPU ABI.  x0/x0 and the old
# symbolic x_* names encode unusable DMA sidebands and must never reappear in
# a delivered assembly program.
file(GLOB GENERATED_ASM "${ROOT}/output/*.asm")
foreach(ASM_PATH IN LISTS GENERATED_ASM)
    file(READ "${ASM_PATH}" ASM_SOURCE)
    if(ASM_SOURCE MATCHES "\"d(load|store)[ \t]+x0,[ \t]*x0")
        message(FATAL_ERROR "DMA x0/x0 placeholder remains in ${ASM_PATH}")
    endif()
    if(ASM_SOURCE MATCHES "\"d(load|store)[ \t]+x_[A-Za-z0-9_]+")
        message(FATAL_ERROR "Symbolic DMA register remains in ${ASM_PATH}")
    endif()
    if(ASM_SOURCE MATCHES "\"d(load|store)" AND
            NOT ASM_SOURCE MATCHES "\"d(load|store)[ \t]+x10,[ \t]*x11")
        message(FATAL_ERROR "DMA instruction does not use x10/x11 in ${ASM_PATH}")
    endif()
endforeach()

file(READ "${ROOT}/outputs/ciphertext_multiply/test_data/VALIDATION.txt" VALIDATION)
if(NOT VALIDATION MATCHES "^PASS")
    message(FATAL_ERROR "FHE reference validation did not pass")
endif()

file(READ "${ROOT}/outputs/ciphertext_multiply/test_data/hardware/abi.json" HARDWARE_ABI)
if(NOT HARDWARE_ABI MATCHES "\"coefficient_bits\": 32")
    message(FATAL_ERROR "Hardware ABI is not uint32")
endif()
if(NOT HARDWARE_ABI MATCHES "\"line_bytes\": 256")
    message(FATAL_ERROR "Hardware ABI does not use 256-byte lines")
endif()
if(NOT HARDWARE_ABI MATCHES "\"dload_flag0_small_bank\": 1")
    message(FATAL_ERROR "Hardware ABI does not select Bank 5 for mod_ctx dload")
endif()
if(NOT HARDWARE_ABI MATCHES "\"small_bank_lines\": 32")
    message(FATAL_ERROR "Hardware ABI does not use the latest 32-line Bank 5")
endif()
if(NOT HARDWARE_ABI MATCHES "\"regular_bank_count\": 5")
    message(FATAL_ERROR "Hardware ABI does not describe the five regular SRAM banks")
endif()
if(NOT HARDWARE_ABI MATCHES "\"regular_bank_lines\": 1024")
    message(FATAL_ERROR "Hardware ABI does not describe 1024 lines per regular SRAM bank")
endif()
if(NOT HARDWARE_ABI MATCHES "\"mod_table_base_line\": \"0x00001400\"")
    message(FATAL_ERROR "Hardware ABI does not freeze MOD_TABLE_BASE_LINE at 0x1400")
endif()
if(NOT HARDWARE_ABI MATCHES "\"physical_context_capacity\": 512")
    message(FATAL_ERROR "Hardware ABI does not describe Bank 5 physical context capacity")
endif()
if(NOT HARDWARE_ABI MATCHES "\"mod_id_bits\": 8")
    message(FATAL_ERROR "Hardware ABI does not enforce the PMODLD MOD_ID width")
endif()
if(NOT HARDWARE_ABI MATCHES "\"mod_id_addressable_lines\": 16")
    message(FATAL_ERROR "Hardware ABI does not distinguish MOD_ID reach from Bank 5 depth")
endif()
if(NOT HARDWARE_ABI MATCHES "\"max_contexts\": 256")
    message(FATAL_ERROR "Hardware ABI does not cap contexts by the 8-bit MOD_ID address space")
endif()
if(NOT HARDWARE_ABI MATCHES "\"rs1_value\": \"HPU_MEM line offset\"")
    message(FATAL_ERROR "Hardware ABI does not freeze custom1 rs1 as the HPU_MEM line offset")
endif()
if(NOT HARDWARE_ABI MATCHES "\"rs2_value\": \"line count\"")
    message(FATAL_ERROR "Hardware ABI does not freeze custom1 rs2 as the nonzero line count")
endif()
if(NOT HARDWARE_ABI MATCHES "\"q_min\": 65537")
    message(FATAL_ERROR "Hardware ABI does not enforce the PE minimum modulus")
endif()
if(NOT HARDWARE_ABI MATCHES "\"q_max\": 4294967295")
    message(FATAL_ERROR "Hardware ABI does not enforce the PE maximum modulus")
endif()
if(NOT HARDWARE_ABI MATCHES "\"mu_bits\": 48")
    message(FATAL_ERROR "Hardware ABI does not describe the PE 48-bit Barrett mu")
endif()
if(NOT HARDWARE_ABI MATCHES "\"reserved_bits\": 48")
    message(FATAL_ERROR "Hardware ABI does not describe the 48 reserved context bits")
endif()
if(NOT HARDWARE_ABI MATCHES "\"stage_payload_words\": 2048")
    message(FATAL_ERROR "Hardware ABI does not provide N/2 physical twiddles per stage")
endif()
if(NOT HARDWARE_ABI MATCHES "\"stage_payload_lines\": 32")
    message(FATAL_ERROR "Hardware ABI stage twiddles do not occupy N/128 HPU lines")
endif()
if(NOT HARDWARE_ABI MATCHES "\"pre_twist_execution\": \"explicit PMUL")
    message(FATAL_ERROR "Hardware ABI does not explicitly execute the negacyclic pre-twist")
endif()
if(NOT HARDWARE_ABI MATCHES "\"intt_post_execution\": \"explicit PMUL")
    message(FATAL_ERROR "Hardware ABI does not explicitly execute INTT normalization/inverse twist")
endif()
if(NOT HARDWARE_ABI MATCHES "\"physical_update\": \"out-of-place per stage")
    message(FATAL_ERROR "Hardware ABI does not freeze NTT/INTT as physical out-of-place")
endif()

file(READ "${ROOT}/outputs/ciphertext_multiply/test_data/hardware/hpu_mem_config.json" HPU_MEM_CONFIG)
if(NOT HPU_MEM_CONFIG MATCHES "\"words_per_line\": 64")
    message(FATAL_ERROR "HPU_MEM configuration does not use 64 uint32 words per line")
endif()
foreach(CSR_OFFSET 0x00 0x04 0x08 0x0c 0x10 0x14 0x18)
    if(NOT HPU_MEM_CONFIG MATCHES "\"offset\": \"${CSR_OFFSET}\"")
        message(FATAL_ERROR "HPU_MEM configuration is missing CSR offset ${CSR_OFFSET}")
    endif()
endforeach()
if(HPU_MEM_CONFIG MATCHES "RTL_CONFIRM_REQUIRED")
    message(FATAL_ERROR "HPU_MEM configuration still marks frozen CSR offsets unresolved")
endif()

file(READ "${ROOT}/outputs/ciphertext_multiply/test_data/hardware/mod_ctx_map.csv" MOD_CTX_MAP)
if(NOT MOD_CTX_MAP MATCHES "barrett_mu48_hex")
    message(FATAL_ERROR "Hardware mod_ctx map does not contain 48-bit Barrett mu")
endif()

file(READ "${ROOT}/outputs/ciphertext_multiply/test_data/hardware/twiddle_map.csv" TWIDDLE_MAP)
file(STRINGS "${ROOT}/outputs/ciphertext_multiply/test_data/hardware/twiddle_map.csv"
    TWIDDLE_ROWS)
foreach(DIRECTION ntt intt)
    foreach(STAGE RANGE 0 11)
        set(STAGE_FOUND 0)
        foreach(TWIDDLE_ROW IN LISTS TWIDDLE_ROWS)
            if(TWIDDLE_ROW MATCHES
                    "^${DIRECTION},0,[0-9]+,butterfly,${STAGE},2048,"
                    AND TWIDDLE_ROW MATCHES ",32$")
                set(STAGE_FOUND 1)
            endif()
        endforeach()
        if(NOT STAGE_FOUND)
            message(FATAL_ERROR
                "Hardware twiddle map does not provide 2048 words/32 lines for ${DIRECTION} stage ${STAGE}")
        endif()
    endforeach()
endforeach()

file(READ "${ROOT}/output/ciphertext_multiply.asm" CIPHERTEXT_ASM)
file(READ "${ROOT}/output/relinearization.asm" RELINEARIZATION_ASM)
file(READ "${ROOT}/output/cmult.asm" CMULT_ASM)
foreach(MARKER
        "Tensor product in NTT domain"
        "MODUP: Q_digit -> full Q union P"
        "Relinearization: KeySwitch(t2, rlk)"
        "MODDOWN stage-1: BConv P -> Q"
        "Compose final ciphertext")
    string(FIND "${CIPHERTEXT_ASM}" "${MARKER}" POSITION)
    if(POSITION EQUAL -1)
        message(FATAL_ERROR "Missing ciphertext multiply stage marker: ${MARKER}")
    endif()
endforeach()

string(FIND "${CMULT_ASM}" "CMULT out0 = a0 * b0" CMULT_OUT0_POSITION)
string(FIND "${CMULT_ASM}" "CMULT out1 = a0 * b1 + a1 * b0" CMULT_OUT1_POSITION)
string(FIND "${CMULT_ASM}" "CMULT out2 = a1 * b1" CMULT_OUT2_POSITION)
if(CMULT_OUT0_POSITION EQUAL -1
        OR CMULT_OUT1_POSITION EQUAL -1
        OR CMULT_OUT2_POSITION EQUAL -1
        OR CMULT_OUT0_POSITION GREATER_EQUAL CMULT_OUT1_POSITION
        OR CMULT_OUT1_POSITION GREATER_EQUAL CMULT_OUT2_POSITION)
    message(FATAL_ERROR "CMult does not compute/store components in out0, out1, out2 order")
endif()

foreach(MARKER
        "KeySwitch(base=t0, switching_component=t2)"
        "Step 6: Add base component to out0"
        "Relinearization final merge: out1 = t1 + ks1")
    string(FIND "${RELINEARIZATION_ASM}" "${MARKER}" POSITION)
    if(POSITION EQUAL -1)
        message(FATAL_ERROR "Missing relinearization composition marker: ${MARKER}")
    endif()
endforeach()

file(READ "${ROOT}/src/operator/ciphertext_multiply.cpp" CIPHERTEXT_SOURCE)
string(FIND "${CIPHERTEXT_SOURCE}"
    "generate_hpu_relinearization_body_asm" SHARED_RELINEARIZATION_POSITION)
if(SHARED_RELINEARIZATION_POSITION EQUAL -1)
    message(FATAL_ERROR "Ciphertext multiply does not call the shared relinearization generator")
endif()
string(FIND "${CIPHERTEXT_SOURCE}"
    "generate_relinearize_t2_body_asm" LEGACY_RELINEARIZATION_POSITION)
if(NOT LEGACY_RELINEARIZATION_POSITION EQUAL -1)
    message(FATAL_ERROR "Ciphertext multiply still contains the legacy relinearization generator")
endif()

file(READ "${ROOT}/src/poly/modup.cpp" MODUP_SOURCE)
file(READ "${ROOT}/src/operator/keyswitch.cpp" KEYSWITCH_SOURCE)
file(READ "${ROOT}/src/poly/auto.cpp" AUTO_SOURCE)
foreach(SOURCE_TEXT MODUP_SOURCE KEYSWITCH_SOURCE AUTO_SOURCE)
    string(FIND "${${SOURCE_TEXT}}"
        "generate_hpu_hybrid_modup_body_asm" LEGACY_HYBRID_MODUP_POSITION)
    if(NOT LEGACY_HYBRID_MODUP_POSITION EQUAL -1)
        message(FATAL_ERROR "${SOURCE_TEXT} still references the removed hybrid ModUp API")
    endif()
endforeach()
foreach(SOURCE_TEXT KEYSWITCH_SOURCE)
    string(FIND "${${SOURCE_TEXT}}"
        "generate_hpu_modup_body_asm" UNIFIED_MODUP_POSITION)
    if(UNIFIED_MODUP_POSITION EQUAL -1)
        message(FATAL_ERROR "${SOURCE_TEXT} does not call the unified full-basis ModUp generator")
    endif()
endforeach()
string(FIND "${AUTO_SOURCE}"
    "generate_hpu_keyswitch_body_asm" AUTO_KEYSWITCH_POSITION)
if(AUTO_KEYSWITCH_POSITION EQUAL -1)
    message(FATAL_ERROR "AUTO does not reuse the complete Galois KeySwitch stream")
endif()

file(READ "${ROOT}/output/modup.asm" MODUP_ASM)
foreach(MARKER
        "MODUP: Q_digit -> full Q union P"
        "Copy Q context 0"
        "Copy Q context 1"
        "Target context 6")
    string(FIND "${MODUP_ASM}" "${MARKER}" POSITION)
    if(POSITION EQUAL -1)
        message(FATAL_ERROR "Unified ModUp stream is missing marker: ${MARKER}")
    endif()
endforeach()

file(READ "${ROOT}/outputs/modup/test_data/params.json" MODUP_PARAMS)
if(NOT MODUP_PARAMS MATCHES "\"output_domain\": \"coefficient/QP\"")
    message(FATAL_ERROR "ModUp test package does not describe a complete Q union P output")
endif()
file(READ "${ROOT}/outputs/modup/test_data/artifact_manifest.csv" MODUP_MANIFEST)
if(NOT MODUP_MANIFEST MATCHES "expected_qp.bin")
    message(FATAL_ERROR "ModUp test package does not contain the complete Q union P golden")
endif()

file(READ "${ROOT}/output/ntt.asm" NTT_ASM)
string(FIND "${NTT_ASM}" "Negacyclic pre-twist: explicit PMUL" NTT_PRE_TWIST_POSITION)
string(FIND "${NTT_ASM}" "pntt p" NTT_STAGE_POSITION)
if(NTT_PRE_TWIST_POSITION EQUAL -1
        OR NTT_STAGE_POSITION EQUAL -1
        OR NTT_PRE_TWIST_POSITION GREATER_EQUAL NTT_STAGE_POSITION)
    message(FATAL_ERROR "NTT stream does not execute the pre-twist before stage 0")
endif()

file(READ "${ROOT}/output/intt.asm" INTT_ASM)
string(FIND "${INTT_ASM}" "pintt p" INTT_STAGE_POSITION)
string(FIND "${INTT_ASM}" "INTT normalize and inverse-twist: explicit PMUL" INTT_POST_POSITION)
if(INTT_STAGE_POSITION EQUAL -1
        OR INTT_POST_POSITION EQUAL -1
        OR INTT_STAGE_POSITION GREATER_EQUAL INTT_POST_POSITION)
    message(FATAL_ERROR "INTT stream does not execute normalization/inverse twist after its stages")
endif()

file(READ "${ROOT}/output/encode.asm" ENCODE_ASM)
string(FIND "${ENCODE_ASM}"
    "ENCODE: host signed-to-RNS input -> NTT plaintext" ENCODE_BOUNDARY_POSITION)
string(FIND "${ENCODE_ASM}"
    "Negacyclic pre-twist: explicit PMUL" ENCODE_NTT_POSITION)
if(ENCODE_BOUNDARY_POSITION EQUAL -1
        OR ENCODE_NTT_POSITION EQUAL -1
        OR ENCODE_BOUNDARY_POSITION GREATER_EQUAL ENCODE_NTT_POSITION)
    message(FATAL_ERROR "Encode stream does not transform host-embedded RNS plaintext")
endif()
file(READ "${ROOT}/outputs/encode/test_data/params.json" ENCODE_PARAMS)
if(NOT ENCODE_PARAMS MATCHES
        "\"input_domain\": \"host-signed-to-RNS/coefficient/Q\"")
    message(FATAL_ERROR "Encode package does not freeze the host signed-to-RNS boundary")
endif()
file(READ "${ROOT}/outputs/encode/test_data/artifact_manifest.csv" ENCODE_MANIFEST)
if(NOT ENCODE_MANIFEST MATCHES "expected_ntt_q.bin[^\n]*4x4096")
    message(FATAL_ERROR "Encode expected output does not contain four Q limbs")
endif()

file(READ "${ROOT}/output/rescale.asm" RESCALE_ASM)
foreach(MARKER
        "RESCALE: rounded drop-last q_3 for 2 component(s)"
        "add floor(q_last/2) in every Q context"
        "reuse ModDown with Q'=q_0..q_2 and P={q_3}"
        "MODDOWN stage-1: BConv P -> Q")
    string(FIND "${RESCALE_ASM}" "${MARKER}" POSITION)
    if(POSITION EQUAL -1)
        message(FATAL_ERROR "Rescale stream is missing marker: ${MARKER}")
    endif()
endforeach()
file(READ "${ROOT}/src/operator/rescale.cpp" RESCALE_SOURCE)
string(FIND "${RESCALE_SOURCE}"
    "generate_hpu_moddown_body_asm" RESCALE_MODDOWN_POSITION)
if(RESCALE_MODDOWN_POSITION EQUAL -1)
    message(FATAL_ERROR "Rescale does not reuse the shared ModDown generator")
endif()
file(READ "${ROOT}/outputs/rescale/test_data/params.json" RESCALE_PARAMS)
if(NOT RESCALE_PARAMS MATCHES
        "\"output_domain\": \"ciphertext/coefficient/Q_without_last\"")
    message(FATAL_ERROR "Rescale package does not describe the dropped output basis")
endif()
file(READ "${ROOT}/outputs/rescale/test_data/artifact_manifest.csv" RESCALE_MANIFEST)
if(NOT RESCALE_MANIFEST MATCHES "expected_qprime.bin[^\n]*2x3x4096")
    message(FATAL_ERROR "Rescale expected output is not two components over three retained Q limbs")
endif()

string(FIND "${CIPHERTEXT_ASM}" "pfree p" PFREE_POSITION)
if(PFREE_POSITION EQUAL -1)
    message(FATAL_ERROR "Ciphertext multiply does not release temporary object slots with pfree")
endif()

foreach(REMOVED_MNEMONIC pshcfg pshuf pseed psample)
    string(FIND "${CIPHERTEXT_ASM}" "${REMOVED_MNEMONIC} " REMOVED_POSITION)
    if(NOT REMOVED_POSITION EQUAL -1)
        message(FATAL_ERROR "Removed instruction appears in ciphertext multiply: ${REMOVED_MNEMONIC}")
    endif()
endforeach()

file(READ "${ROOT}/outputs/rv_interface_smoke/test_data/expected_decode.csv" RV_EXPECTED_DECODE)
if(NOT RV_EXPECTED_DECODE MATCHES "0x603FC00B,0x0C07F80,custom0,\"pmodld 255\"")
    message(FATAL_ERROR "RV decode expectations are missing the 8-bit MOD_ID pmodld encoding")
endif()
if(NOT RV_EXPECTED_DECODE MATCHES "0x8140000B,0x1028000,custom0,\"pfree p5\"")
    message(FATAL_ERROR "RV decode expectations are missing the architectural pfree encoding")
endif()
if(NOT RV_EXPECTED_DECODE MATCHES "0x00B5292B,0x2000424,custom1,\"dload x10, x11, p4, 2, 1\"")
    message(FATAL_ERROR "RV decode expectations are missing mod_ctx small-bank flag[0]")
endif()

file(READ "${ROOT}/outputs/rv_interface_smoke/test_data/negative_cases.asm.txt" RV_NEGATIVE_CASES)
foreach(REMOVED_MNEMONIC pshcfg pshuf pseed psample)
    string(FIND "${RV_NEGATIVE_CASES}" "${REMOVED_MNEMONIC} " NEGATIVE_POSITION)
    if(NEGATIVE_POSITION EQUAL -1)
        message(FATAL_ERROR "RV negative cases do not reject removed instruction: ${REMOVED_MNEMONIC}")
    endif()
endforeach()
string(FIND "${RV_NEGATIVE_CASES}" "dload x0, x0, p0, 3, 0" RESERVED_DLOAD_TYPE_POSITION)
if(RESERVED_DLOAD_TYPE_POSITION EQUAL -1)
    message(FATAL_ERROR "RV negative cases do not reject reserved dload load_type=3")
endif()

function(CHECK_OBJECT_LIFECYCLE RELATIVE_PATH)
    foreach(SLOT RANGE 0 7)
        set(LIVE_${SLOT} 0)
    endforeach()

    file(STRINGS "${ROOT}/${RELATIVE_PATH}" ASM_LINES)
    foreach(LINE IN LISTS ASM_LINES)
        if(LINE MATCHES "\"dload [^,]+, [^,]+, p([0-7]), [0-2], [01]")
            set(SLOT "${CMAKE_MATCH_1}")
            if(LIVE_${SLOT})
                message(FATAL_ERROR "${RELATIVE_PATH}: dload overwrites live object p${SLOT}")
            endif()
            set(LIVE_${SLOT} 1)
        elseif(LINE MATCHES "\"(padd|psub|pmul|pmac|pntt|pintt) p([0-7]),")
            set(SLOT "${CMAKE_MATCH_2}")
            set(LIVE_${SLOT} 1)
        elseif(LINE MATCHES "\"pfree p([0-7])")
            set(SLOT "${CMAKE_MATCH_1}")
            if(NOT LIVE_${SLOT})
                message(FATAL_ERROR "${RELATIVE_PATH}: pfree targets non-live object p${SLOT}")
            endif()
            set(LIVE_${SLOT} 0)
        elseif(LINE MATCHES "\"dstore [^,]+, [^,]+, p([0-7]), ([01])")
            set(SLOT "${CMAKE_MATCH_1}")
            set(RELEASE "${CMAKE_MATCH_2}")
            if(RELEASE EQUAL 1)
                if(NOT LIVE_${SLOT})
                    message(FATAL_ERROR "${RELATIVE_PATH}: dstore rel=1 targets non-live object p${SLOT}")
                endif()
                set(LIVE_${SLOT} 0)
            endif()
        endif()
    endforeach()
endfunction()

foreach(CASE_NAME ntt intt encode rescale mm bconv pmult cmult modup moddown auto keyswitch relinearization ciphertext_multiply)
    CHECK_OBJECT_LIFECYCLE("output/${CASE_NAME}.asm")
endforeach()

function(CHECK_MOD_CONTEXT_LOAD RELATIVE_PATH)
    file(STRINGS "${ROOT}/${RELATIVE_PATH}" ASM_LINES)
    foreach(LINE IN LISTS ASM_LINES)
        if(LINE MATCHES "\"dload [^,]+, [^,]+, p[0-7], [01], 1")
            message(FATAL_ERROR
                "${RELATIVE_PATH}: non-mod_ctx dload requests reserved small Bank 5")
        elseif(LINE MATCHES "\"dload [^,]+, [^,]+, p[0-7], 2, 0")
            message(FATAL_ERROR "${RELATIVE_PATH}: mod_ctx dload does not set small-bank flag[0]")
        endif()
    endforeach()
endfunction()

foreach(CASE_NAME ntt intt encode rescale bconv pmult cmult modup moddown auto keyswitch relinearization ciphertext_multiply)
    CHECK_MOD_CONTEXT_LOAD("output/${CASE_NAME}.asm")
endforeach()

function(CHECK_TERMINAL_PSYNC RELATIVE_PATH)
    set(PSYNC_COUNT 0)
    set(LAST_OPCODE "")
    file(STRINGS "${ROOT}/${RELATIVE_PATH}" ASM_LINES)
    foreach(LINE IN LISTS ASM_LINES)
        if(LINE MATCHES "^[ \t]*\"?(padd|psub|pmul|pmac|pntt|pintt|pmodld|pfree|psync|dload|dstore)")
            set(LAST_OPCODE "${CMAKE_MATCH_1}")
            if(LAST_OPCODE STREQUAL "psync")
                math(EXPR PSYNC_COUNT "${PSYNC_COUNT} + 1")
            endif()
        endif()
    endforeach()
    if(NOT PSYNC_COUNT EQUAL 1)
        message(FATAL_ERROR
            "${RELATIVE_PATH}: complete stream must contain exactly one psync, found ${PSYNC_COUNT}")
    endif()
    if(NOT LAST_OPCODE STREQUAL "psync")
        message(FATAL_ERROR
            "${RELATIVE_PATH}: psync must be the final instruction, found ${LAST_OPCODE}")
    endif()
endfunction()

foreach(CASE_NAME ntt intt encode rescale mm bconv pmult cmult modup moddown auto keyswitch relinearization ciphertext_multiply)
    CHECK_TERMINAL_PSYNC("output/${CASE_NAME}.asm")
endforeach()
CHECK_TERMINAL_PSYNC("outputs/rv_interface_smoke/rv_interface_smoke.asm")

foreach(CASE_NAME ntt intt encode rescale mm bconv pmult cmult modup moddown auto keyswitch relinearization ciphertext_multiply)
    foreach(EXECUTABLE_FILE
            "output/${CASE_NAME}.cpp"
            "outputs/${CASE_NAME}/${CASE_NAME}.cpp")
        file(READ "${ROOT}/${EXECUTABLE_FILE}" EXECUTABLE_SOURCE)
        if(NOT EXECUTABLE_SOURCE MATCHES "register uintptr_t hpu_rs1 __asm__\\(\"x10\"\\)"
                AND NOT CASE_NAME STREQUAL "mm")
            message(FATAL_ERROR "${EXECUTABLE_FILE}: executable backend does not bind x10")
        endif()
        if(NOT EXECUTABLE_SOURCE MATCHES "register uintptr_t hpu_rs2 __asm__\\(\"x11\"\\)"
                AND NOT CASE_NAME STREQUAL "mm")
            message(FATAL_ERROR "${EXECUTABLE_FILE}: executable backend does not bind x11")
        endif()
        if(EXECUTABLE_SOURCE MATCHES "hpu_rs2 __asm__\\(\"x11\"\\) = 0;")
            message(FATAL_ERROR
                "${EXECUTABLE_FILE}: zero-length DMA sideband violates DLOAD/DSTORE ABI")
        endif()
        if(NOT EXECUTABLE_SOURCE MATCHES "__asm__ volatile\\(\".word 0x[0-9A-F]+")
            message(FATAL_ERROR "${EXECUTABLE_FILE}: executable backend has no fixed .word")
        endif()
        if(EXECUTABLE_SOURCE MATCHES "__asm__ volatile\\([^\n]*d(load|store)")
            message(FATAL_ERROR "${EXECUTABLE_FILE}: GNU-unknown HPU mnemonic remains")
        endif()
    endforeach()
    foreach(REQUIRED_EXECUTABLE_ARTIFACT
            "outputs/${CASE_NAME}/${CASE_NAME}.c"
            "outputs/${CASE_NAME}/${CASE_NAME}.h"
            "outputs/${CASE_NAME}/dma_relocation_manifest.csv")
        if(NOT EXISTS "${ROOT}/${REQUIRED_EXECUTABLE_ARTIFACT}")
            message(FATAL_ERROR "Missing executable artifact: ${REQUIRED_EXECUTABLE_ARTIFACT}")
        endif()
    endforeach()
endforeach()

file(STRINGS "${ROOT}/outputs/ciphertext_multiply/ciphertext_multiply.inst32" INST32_LINES)
list(LENGTH INST32_LINES INST32_COUNT)
if(INST32_COUNT LESS 2000)
    message(FATAL_ERROR "Ciphertext multiply instruction stream is unexpectedly short")
endif()
file(STRINGS "${ROOT}/outputs/ciphertext_multiply/ciphertext_multiply.cmd26" CMD26_LINES)
list(LENGTH CMD26_LINES CMD26_COUNT)
if(NOT CMD26_COUNT EQUAL INST32_COUNT)
    message(FATAL_ERROR "32-bit instruction and 26-bit precode counts differ")
endif()

file(STRINGS "${ROOT}/outputs/relinearization/relinearization.inst32" RELIN_INST32_LINES)
list(LENGTH RELIN_INST32_LINES RELIN_INST32_COUNT)
if(RELIN_INST32_COUNT LESS 1000)
    message(FATAL_ERROR "Relinearization instruction stream is unexpectedly short")
endif()
file(STRINGS "${ROOT}/outputs/relinearization/relinearization.cmd26" RELIN_CMD26_LINES)
list(LENGTH RELIN_CMD26_LINES RELIN_CMD26_COUNT)
if(NOT RELIN_CMD26_COUNT EQUAL RELIN_INST32_COUNT)
    message(FATAL_ERROR "Relinearization 32-bit instruction and 26-bit precode counts differ")
endif()

file(STRINGS "${ROOT}/outputs/encode/encode.inst32" ENCODE_INST32_LINES)
list(LENGTH ENCODE_INST32_LINES ENCODE_INST32_COUNT)
file(STRINGS "${ROOT}/outputs/encode/encode.cmd26" ENCODE_CMD26_LINES)
list(LENGTH ENCODE_CMD26_LINES ENCODE_CMD26_COUNT)
if(ENCODE_INST32_COUNT LESS 100 OR NOT ENCODE_CMD26_COUNT EQUAL ENCODE_INST32_COUNT)
    message(FATAL_ERROR "Encode instruction/precode stream is missing or inconsistent")
endif()

file(STRINGS "${ROOT}/outputs/rescale/rescale.inst32" RESCALE_INST32_LINES)
list(LENGTH RESCALE_INST32_LINES RESCALE_INST32_COUNT)
file(STRINGS "${ROOT}/outputs/rescale/rescale.cmd26" RESCALE_CMD26_LINES)
list(LENGTH RESCALE_CMD26_LINES RESCALE_CMD26_COUNT)
if(RESCALE_INST32_COUNT LESS 100 OR NOT RESCALE_CMD26_COUNT EQUAL RESCALE_INST32_COUNT)
    message(FATAL_ERROR "Rescale instruction/precode stream is missing or inconsistent")
endif()

file(SHA256 "${ROOT}/outputs/relinearization/test_data/expected_q.bin" RELIN_EXPECTED_HASH)
file(SHA256 "${ROOT}/outputs/ciphertext_multiply/test_data/expected/ciphertext_out_q.bin"
    CIPHERTEXT_EXPECTED_HASH)
if(NOT RELIN_EXPECTED_HASH STREQUAL CIPHERTEXT_EXPECTED_HASH)
    message(FATAL_ERROR "Standalone relinearization output differs from ciphertext multiply output")
endif()

file(WRITE "${ROOT}/outputs/DELIVERY_REPORT.txt"
    "SOFTWARE_DELIVERY=PASS\n"
    "FHE_REFERENCE=PASS\n"
    "ASM_ENCODING=PASS\n"
    "PRECODE_CMD26=PASS\n"
    "MOD_CTX_SMALL_BANK_FLAG=PASS\n"
    "DMA_RELOCATABLE_EXECUTABLE_BACKEND=PASS\n"
    "TERMINAL_PSYNC=PASS\n"
    "INSTRUCTION_SET_11=PASS\n"
    "PFREE_LIFECYCLE=PASS\n"
    "RV_INTERFACE_SMOKE=PASS\n"
    "OPERATOR_UT_PACKAGES=PASS\n"
    "HARDWARE_UINT32_IMAGES=PASS\n"
    "HPU_LINE_LAYOUT_256B=PASS\n"
    "CUSTOM1_LINE_SIDEBAND=PASS\n"
    "HPU_MEM_CSR_MAP=PASS\n"
    "MOD_CTX_Q32_MU48=PASS\n"
    "MOD_TABLE_BASE_0X1400=PASS\n"
    "STAGE_TWIDDLE_LAYOUT=PASS\n"
    "NEGACYCLIC_FACTORS_EXPLICIT=PASS\n"
    "NTT_PHYSICAL_OUT_OF_PLACE=PASS\n"
    "ENCODE_HOST_RNS_BOUNDARY=PASS\n"
    "RESCALE_ROUNDED_DROP_LAST=PASS\n"
    "ENCODE_INST32_COUNT=${ENCODE_INST32_COUNT}\n"
    "RESCALE_INST32_COUNT=${RESCALE_INST32_COUNT}\n"
    "RELINEARIZATION_REUSES_KEYSWITCH=PASS\n"
    "RELINEARIZATION_INST32_COUNT=${RELIN_INST32_COUNT}\n"
    "CIPHERTEXT_MULTIPLY_INST32_COUNT=${INST32_COUNT}\n"
    "TEST_VECTOR_SCOPE=FUNCTIONAL_ONLY\n"
    "HARDWARE_EXECUTION=CONDITIONAL\n"
    "PENDING=target RTL/board execution and external monitor evidence\n")

message(STATUS "HPU software delivery check PASS (${INST32_COUNT} ciphertext-multiply instructions)")
