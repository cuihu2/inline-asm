#include "poly/auto.hpp"
#include "operator/keyswitch.hpp"
#include "util/hpu_asm.hpp"

#include <sstream>
#include <string>

namespace {
bool is_power_of_two(int x) { return x > 0 && (x & (x - 1)) == 0; }
} // namespace

std::string generate_hpu_auto_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    int auto_idx,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (num_q <= 0 || num_p <= 0 || !is_power_of_two(N) || dnum <= 0
        || !hpu::fits_ntt_object(N)
        || num_q % dnum != 0
        || num_q + num_p > hpu::kMaxModContexts) return "";

    if (auto_idx != 1) {
        asm_code << "        // Unsupported AUTO index: only index 1 / Galois element 3 is frozen\n";
        return asm_code.str();
    }

    asm_code << "        /* AUTO index 1: CPU has already applied negacyclic x -> x^3 */\n";
    asm_code << "        /* HPU stage: switch rotated c1 from sigma_3(s) back to s. */\n";
    asm_code << generate_hpu_keyswitch_body_asm(
        N, num_q, num_p, dnum, append_psync);

    return asm_code.str();
}

std::string generate_hpu_auto_asm(
	int N,
	int num_q,
	int num_p,
	int dnum,
	int auto_idx,
	bool append_psync)
{
	std::ostringstream asm_code;
	asm_code << "void hpu_auto_N" << N << "_Q" << num_q << "_P" << num_p << "_D" << dnum
			 << "_A" << auto_idx << "(void) {\n";

			if (num_q <= 0 || num_p <= 0 || !is_power_of_two(N) || dnum <= 0
				|| !hpu::fits_ntt_object(N)
				|| num_q % dnum != 0
				|| num_q + num_p > hpu::kMaxModContexts) {
			asm_code << "    // Invalid config: require power-of-two N fitting 1024 lines, valid digits, and at most 256 mod contexts\n";
		asm_code << "}\n";
		return asm_code.str();
	}

	asm_code << "    __asm__ volatile(\n";
	asm_code << "        /* AUTO: shuffle ct0/ct1, then keyswitch ct1 and fold ct0 into out0 */\n";
	asm_code << generate_hpu_auto_body_asm(N, num_q, num_p, dnum, auto_idx, append_psync);
	asm_code << "        : \n";
	asm_code << "        : \n";
	asm_code << "        : \"memory\"\n";
	asm_code << "    );\n";
	asm_code << "}\n";

	return asm_code.str();
}
