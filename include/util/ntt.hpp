#pragma once

#include <string>

std::string generate_hpu_ntt_body_asm(
        int N,
        int obj_poly,
        int scratch_obj,
        int twiddle_obj,
        bool append_psync = false);

std::string generate_hpu_intt_body_asm(
        int N,
        int obj_poly,
        int scratch_obj,
        int twiddle_obj,
        bool append_psync = false);

std::string generate_hpu_ntt_asm(
        int N,
        int obj_poly,
        int scratch_obj,
        int twiddle_obj,
        int mod_ctx_obj,
        bool append_psync = true);

std::string generate_hpu_intt_asm(
        int N,
        int obj_poly,
        int scratch_obj,
        int twiddle_obj,
        int mod_ctx_obj,
        bool append_psync = true);
