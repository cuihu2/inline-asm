#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "config/fhe_test_config.hpp"
#include "util/bconv.hpp"
#include "util/mm.hpp"
#include "util/ntt.hpp"
#include "poly/auto.hpp"
#include "poly/cmult.hpp"
#include "poly/moddown.hpp"
#include "poly/modup.hpp"
#include "poly/pmult.hpp"
#include "operator/keyswitch.hpp"
#include "operator/relinearization.hpp"
#include "operator/ciphertext_multiply.hpp"
#include "scheme/bgv/ciphertext_multiply.hpp"
#include "scheme/bgv/modswitch.hpp"
#include "scheme/bfv/ciphertext_multiply.hpp"
#include "scheme/bfv/modswitch.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"
#include "scheme/ckks/ciphertext_multiply.hpp"
#include "scheme/ckks/relinearize.hpp"
#include "scheme/ckks/rescale.hpp"
#include "scheme/ckks/rotate.hpp"

namespace {

enum class OutputMode {
	CPP,
	ASM,
	BOTH
};

OutputMode g_output_mode = OutputMode::BOTH;

struct NttConfig {
	int N;
	int obj_poly;
	int twiddle_obj;
	int mod_ctx_obj;
};

struct MmConfig {
	int obj_a;
	int obj_b;
	int obj_c;
	int mod_ctx_obj;
};

struct BconvConfig {
	int num_q;
	int num_p;
	int obj_q_base;
	int obj_tmp_base;
	int obj_p_base;
	int obj_qhat_inv_base;
	int obj_qhat_modp_base;
	int mod_ctx_q_base;
	int mod_ctx_p_base;
};

struct PmultConfig {
	int num_q;
	int ct0_base;
	int ct1_base;
	int pt_base;
	int out0_base;
	int out1_base;
	int mod_ctx_q_base;
};

struct CmultConfig {
	int num_q;
	int a0_base;
	int a1_base;
	int b0_base;
	int b1_base;
	int out0_base;
	int out1_base;
	int out2_base;
	int mod_ctx_q_base;
};

struct ModdownConfig {
	int num_q;
	int num_p;
	int q_base;
	int p_base;
	int tmp_base;
	int qcorr_base;
	int phat_inv_base;
	int phat_modq_base;
	int mod_ctx_p_base;
	int mod_ctx_q_base;
};

struct AutoConfig {
	int N;
	int num_q;
	int num_p;
	int dnum;
	int auto_idx;
};

struct CiphertextMultiplyConfig {
	int N;
	int num_q;
	int num_p;
	int dnum;
};

struct RescaleConfig {
	int num_q;
	int num_components;
};

struct BgvModswitchConfig {
	int num_q;
	int num_p;
	int num_components;
};

struct BfvConfig {
	int N;
	int num_q;
	int num_p;
	int num_b;
	int dnum;
	std::uint64_t plaintext_modulus;
};

NttConfig g_ntt_cfg{};
constexpr MmConfig kMmCfg{0, 1, 2, 3};
BconvConfig g_bconv_cfg{};
PmultConfig g_pmult_cfg{};
CmultConfig g_cmult_cfg{};
ModdownConfig g_moddown_cfg{};
AutoConfig g_auto_cfg{};
CiphertextMultiplyConfig g_ciphertext_multiply_cfg{};
RescaleConfig g_rescale_cfg{};
BgvModswitchConfig g_bgv_modswitch_cfg{};
BfvConfig g_bfv_cfg{};

void configure_generators(const hpu::test::FheTestConfig& config)
{
	const int N = static_cast<int>(config.N);
	const int num_q = static_cast<int>(config.num_q);
	const int num_p = static_cast<int>(config.num_p);
	const int dnum = static_cast<int>(config.dnum);
	const int auto_index = static_cast<int>(config.auto_index);

	g_ntt_cfg = {N, 0, 1, 2};
	g_bconv_cfg = {
		num_q, num_p,
		0, 1, 2, 3, 4, 5, 6};
	g_pmult_cfg = {num_q, 0, 1, 2, 3, 4, 5};
	g_cmult_cfg = {num_q, 0, 1, 2, 3, 4, 5, 6, 7};
	g_moddown_cfg = {num_q, num_p, 0, 1, 2, 3, 4, 5, 6, 7};
	g_auto_cfg = {N, num_q, num_p, dnum, auto_index};
	g_ciphertext_multiply_cfg = {N, num_q, num_p, dnum};
	g_rescale_cfg = {num_q, 2};
	g_bgv_modswitch_cfg = {num_q, num_p, 2};
	g_bfv_cfg = {
		N, num_q, num_p, static_cast<int>(config.bfv_num_b), dnum,
		config.plaintext_modulus};
}

void test_bfv_ciphertext_multiply_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/bfv_ciphertext_multiply.cpp")
			<< hpu::scheme::bfv::generate_ciphertext_multiply_asm(
				g_bfv_cfg.N, g_bfv_cfg.num_q, g_bfv_cfg.num_p,
				g_bfv_cfg.num_b, g_bfv_cfg.dnum,
				g_bfv_cfg.plaintext_modulus, true);
	}
	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/bfv_ciphertext_multiply.asm")
			<< hpu::scheme::bfv::generate_ciphertext_multiply_body_asm(
				g_bfv_cfg.N, g_bfv_cfg.num_q, g_bfv_cfg.num_p,
				g_bfv_cfg.num_b, g_bfv_cfg.dnum,
				g_bfv_cfg.plaintext_modulus, true);
	}
}

void test_bfv_modswitch_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/bfv_modswitch.cpp")
			<< hpu::scheme::bfv::generate_modswitch_asm(
				g_bfv_cfg.num_q, 2, true);
	}
	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/bfv_modswitch.asm")
			<< hpu::scheme::bfv::generate_modswitch_body_asm(
				g_bfv_cfg.num_q, 2, true);
	}
}

void test_ckks_rescale_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/ckks_rescale.cpp")
			<< hpu::scheme::ckks::generate_rescale_asm(
				g_rescale_cfg.num_q, g_rescale_cfg.num_components, true);
		std::cout << "Saved CKKS Rescale ASM to output/ckks_rescale.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/ckks_rescale.asm")
			<< hpu::scheme::ckks::generate_rescale_body_asm(
				g_rescale_cfg.num_q, g_rescale_cfg.num_components, true);
		std::cout << "Saved CKKS Rescale body ASM to output/ckks_rescale.asm\n";
	}
}

void test_ckks_ciphertext_multiply_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/ckks_ciphertext_multiply.cpp")
			<< hpu::scheme::ckks::generate_ciphertext_multiply_asm(
				g_ciphertext_multiply_cfg.N,
				g_ciphertext_multiply_cfg.num_q,
				g_ciphertext_multiply_cfg.num_p,
				g_ciphertext_multiply_cfg.dnum,
				true);
		std::cout << "Saved CKKS ciphertext multiply ASM to output/ckks_ciphertext_multiply.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/ckks_ciphertext_multiply.asm")
			<< hpu::scheme::ckks::generate_ciphertext_multiply_body_asm(
				g_ciphertext_multiply_cfg.N,
				g_ciphertext_multiply_cfg.num_q,
				g_ciphertext_multiply_cfg.num_p,
				g_ciphertext_multiply_cfg.dnum,
				true);
		std::cout << "Saved CKKS ciphertext multiply body ASM to output/ckks_ciphertext_multiply.asm\n";
	}
}

void test_bgv_ciphertext_multiply_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/bgv_ciphertext_multiply.cpp")
			<< hpu::scheme::bgv::generate_ciphertext_multiply_asm(
				g_ciphertext_multiply_cfg.N,
				g_ciphertext_multiply_cfg.num_q,
				g_ciphertext_multiply_cfg.num_p,
				g_ciphertext_multiply_cfg.dnum,
				true);
		std::cout << "Saved BGV ciphertext multiply ASM to output/bgv_ciphertext_multiply.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/bgv_ciphertext_multiply.asm")
			<< hpu::scheme::bgv::generate_ciphertext_multiply_body_asm(
				g_ciphertext_multiply_cfg.N,
				g_ciphertext_multiply_cfg.num_q,
				g_ciphertext_multiply_cfg.num_p,
				g_ciphertext_multiply_cfg.dnum,
				true);
		std::cout << "Saved BGV ciphertext multiply body ASM to output/bgv_ciphertext_multiply.asm\n";
	}
}

void test_bgv_modswitch_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/bgv_modswitch.cpp")
			<< hpu::scheme::bgv::generate_modswitch_asm(
				g_bgv_modswitch_cfg.num_q,
				g_bgv_modswitch_cfg.num_p,
				g_bgv_modswitch_cfg.num_components,
				true);
		std::cout << "Saved BGV ModSwitch ASM to output/bgv_modswitch.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/bgv_modswitch.asm")
			<< hpu::scheme::bgv::generate_modswitch_body_asm(
				g_bgv_modswitch_cfg.num_q,
				g_bgv_modswitch_cfg.num_p,
				g_bgv_modswitch_cfg.num_components,
				true);
		std::cout << "Saved BGV ModSwitch body ASM to output/bgv_modswitch.asm\n";
	}
}

void test_intt_codegen() {
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string intt = generate_hpu_intt_asm(
		g_ntt_cfg.N,
		g_ntt_cfg.obj_poly,
		g_ntt_cfg.twiddle_obj,
		g_ntt_cfg.mod_ctx_obj,
		true);
	std::ofstream("output/intt.cpp") << intt;
	std::cout << "Saved intt ASM to output/intt.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string intt_body = generate_hpu_intt_asm(
		g_ntt_cfg.N,
		g_ntt_cfg.obj_poly,
		g_ntt_cfg.twiddle_obj,
		g_ntt_cfg.mod_ctx_obj,
		true);
	std::ofstream("output/intt.asm") << intt_body;
	std::cout << "Saved intt body ASM to output/intt.asm\n";
	}
}

void test_ntt_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string ntt = generate_hpu_ntt_asm(
		g_ntt_cfg.N,
		g_ntt_cfg.obj_poly,
		g_ntt_cfg.twiddle_obj,
		g_ntt_cfg.mod_ctx_obj,
		true);
	std::ofstream("output/ntt.cpp") << ntt;
	std::cout << "Saved ntt ASM to output/ntt.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string ntt_body = generate_hpu_ntt_asm(
		g_ntt_cfg.N,
		g_ntt_cfg.obj_poly,
		g_ntt_cfg.twiddle_obj,
		g_ntt_cfg.mod_ctx_obj,
		true);
	std::ofstream("output/ntt.asm") << ntt_body;
	std::cout << "Saved ntt body ASM to output/ntt.asm\n";
	}
}

void test_mm_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string mm = generate_hpu_mm_asm(
		kMmCfg.obj_a,
		kMmCfg.obj_b,
		kMmCfg.obj_c,
		kMmCfg.mod_ctx_obj,
		true);
	std::ofstream("output/mm.cpp") << mm;
	std::cout << "Saved mm ASM to output/mm.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string mm_body = generate_hpu_mm_asm(
		kMmCfg.obj_a,
		kMmCfg.obj_b,
		kMmCfg.obj_c,
		kMmCfg.mod_ctx_obj,
		true);
	std::ofstream("output/mm.asm") << mm_body;
	std::cout << "Saved mm body ASM to output/mm.asm\n";
	}
}

void test_bconv_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string bconv = generate_hpu_bconv_asm(
		g_bconv_cfg.num_q,
		g_bconv_cfg.num_p,
		0,
		true);
	std::ofstream("output/bconv.cpp") << bconv;
	std::cout << "Saved bconv ASM to output/bconv.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string bconv_body = generate_hpu_bconv_body_asm(
		g_bconv_cfg.num_q,
		g_bconv_cfg.num_p,
		0,
		true);
	std::ofstream("output/bconv.asm") << bconv_body;
	std::cout << "Saved bconv body ASM to output/bconv.asm\n";
	}
}

void test_pmult_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string pmult = generate_hpu_pmult_asm(
		g_pmult_cfg.num_q,
		true);
	std::ofstream("output/pmult.cpp") << pmult;
	std::cout << "Saved pmult ASM to output/pmult.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string pmult_body = generate_hpu_pmult_body_asm(
		g_pmult_cfg.num_q,
		true);
	std::ofstream("output/pmult.asm") << pmult_body;
	std::cout << "Saved pmult body ASM to output/pmult.asm\n";
	}
}

void test_cmult_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string cmult = generate_hpu_cmult_asm(
		g_cmult_cfg.num_q,
		true);
	std::ofstream("output/cmult.cpp") << cmult;
	std::cout << "Saved cmult ASM to output/cmult.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string cmult_body = generate_hpu_cmult_body_asm(
		g_cmult_cfg.num_q,
		true);
	std::ofstream("output/cmult.asm") << cmult_body;
	std::cout << "Saved cmult body ASM to output/cmult.asm\n";
	}
}

void test_modup_codegen()
{
		if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
			std::string modup = generate_hpu_modup_asm(
				g_ciphertext_multiply_cfg.num_q,
				g_ciphertext_multiply_cfg.num_p,
				g_ciphertext_multiply_cfg.num_q / g_ciphertext_multiply_cfg.dnum,
				0,
				true);
	std::ofstream("output/modup.cpp") << modup;
	std::cout << "Saved modup ASM to output/modup.cpp\n";
	}

		if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
			std::string modup_body = generate_hpu_modup_body_asm(
				g_ciphertext_multiply_cfg.num_q,
				g_ciphertext_multiply_cfg.num_p,
				g_ciphertext_multiply_cfg.num_q / g_ciphertext_multiply_cfg.dnum,
				0,
				true);
	std::ofstream("output/modup.asm") << modup_body;
	std::cout << "Saved modup body ASM to output/modup.asm\n";
	}
}

void test_auto_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string auto_code = generate_hpu_auto_asm(
		g_auto_cfg.N,
		g_auto_cfg.num_q,
		g_auto_cfg.num_p,
		g_auto_cfg.dnum,
		g_auto_cfg.auto_idx,
		true);
	std::ofstream("output/auto.cpp") << auto_code;
	std::cout << "Saved auto ASM to output/auto.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string auto_body = generate_hpu_auto_body_asm(
		g_auto_cfg.N,
		g_auto_cfg.num_q,
		g_auto_cfg.num_p,
		g_auto_cfg.dnum,
		g_auto_cfg.auto_idx,
		true);
	std::ofstream("output/auto.asm") << auto_body;
	std::cout << "Saved auto body ASM to output/auto.asm\n";
	}
}

void test_ckks_rotate_codegen()
{
	constexpr std::uint32_t galois_element = 3;
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/ckks_rotate.cpp")
			<< hpu::scheme::ckks::generate_rotate_asm(
				g_auto_cfg.N,
				g_auto_cfg.num_q,
				g_auto_cfg.num_p,
				g_auto_cfg.dnum,
				galois_element,
				true);
		std::cout << "Saved CKKS fused Rotate ASM to output/ckks_rotate.cpp\n";
	}
	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/ckks_rotate.asm")
			<< hpu::scheme::ckks::generate_rotate_body_asm(
				g_auto_cfg.N,
				g_auto_cfg.num_q,
				g_auto_cfg.num_p,
				g_auto_cfg.dnum,
				galois_element,
				true);
		std::cout << "Saved CKKS fused Rotate body to output/ckks_rotate.asm\n";
	}
}

void test_ckks_standalone_ntt_kernels_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/ckks_relinearize_ntt.cpp")
			<< hpu::scheme::ckks::generate_relinearize_ntt_asm(
				g_ciphertext_multiply_cfg.N,
				g_ciphertext_multiply_cfg.num_q,
				g_ciphertext_multiply_cfg.num_p,
				g_ciphertext_multiply_cfg.dnum,
				true);
		std::ofstream("output/ckks_rescale_ntt.cpp")
			<< hpu::scheme::ckks::generate_rescale_ntt_asm(
				g_ciphertext_multiply_cfg.N,
				g_ciphertext_multiply_cfg.num_q,
				true);
	}
	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::ofstream("output/ckks_relinearize_ntt.asm")
			<< hpu::scheme::ckks::generate_relinearize_ntt_body_asm(
				g_ciphertext_multiply_cfg.N,
				g_ciphertext_multiply_cfg.num_q,
				g_ciphertext_multiply_cfg.num_p,
				g_ciphertext_multiply_cfg.dnum,
				true);
		std::ofstream("output/ckks_rescale_ntt.asm")
			<< hpu::scheme::ckks::generate_rescale_ntt_body_asm(
				g_ciphertext_multiply_cfg.N,
				g_ciphertext_multiply_cfg.num_q,
				true);
	}
	std::cout << "Saved standalone SEAL-facing CKKS Relinearize/Rescale kernels\n";
}

void test_ckks_pointwise_codegen()
{
	using WrapperGenerator = std::string (*)(int, bool);
	using BodyGenerator = std::string (*)(int, bool, bool);
	struct PointwiseCase {
		const char* stem;
		WrapperGenerator wrapper;
		BodyGenerator body;
	};
	const PointwiseCase cases[] {
		{"ckks_add", hpu::scheme::ckks::generate_add_asm,
		 hpu::scheme::ckks::generate_add_body_asm},
		{"ckks_subtract", hpu::scheme::ckks::generate_subtract_asm,
		 hpu::scheme::ckks::generate_subtract_body_asm},
		{"ckks_multiply_plain", hpu::scheme::ckks::generate_multiply_plain_asm,
		 hpu::scheme::ckks::generate_multiply_plain_body_asm},
		{"ckks_add_plain", hpu::scheme::ckks::generate_add_plain_asm,
		 hpu::scheme::ckks::generate_add_plain_body_asm},
		{"ckks_subtract_plain", hpu::scheme::ckks::generate_subtract_plain_asm,
		 hpu::scheme::ckks::generate_subtract_plain_body_asm},
	};
	for (const auto& pointwise : cases) {
		if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
			std::ofstream(std::string("output/") + pointwise.stem + ".cpp")
				<< pointwise.wrapper(g_ciphertext_multiply_cfg.num_q, true);
		}
		if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
			std::ofstream(std::string("output/") + pointwise.stem + ".asm")
				<< pointwise.body(
					g_ciphertext_multiply_cfg.num_q,
					true,
					true);
		}
	}
	std::cout << "Saved zero-transform CKKS Add/Sub/Plain kernels\n";
}

void test_moddown_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string moddown = generate_hpu_moddown_asm(
		g_moddown_cfg.num_q,
		g_moddown_cfg.num_p,
		true);
	std::ofstream("output/moddown.cpp") << moddown;
	std::cout << "Saved moddown ASM to output/moddown.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string moddown_body = generate_hpu_moddown_body_asm(
		g_moddown_cfg.num_q,
		g_moddown_cfg.num_p,
		true);
	std::ofstream("output/moddown.asm") << moddown_body;
	std::cout << "Saved moddown body ASM to output/moddown.asm\n";
	}
}

void test_keyswitch_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string keyswitch = generate_hpu_keyswitch_asm(
			g_ciphertext_multiply_cfg.N,
			g_ciphertext_multiply_cfg.num_q,
			g_ciphertext_multiply_cfg.num_p,
			g_ciphertext_multiply_cfg.dnum,
			true);
	std::ofstream("output/keyswitch.cpp") << keyswitch;
	std::cout << "Saved keyswitch ASM to output/keyswitch.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string keyswitch_body = generate_hpu_keyswitch_body_asm(
			g_ciphertext_multiply_cfg.N,
			g_ciphertext_multiply_cfg.num_q,
			g_ciphertext_multiply_cfg.num_p,
			g_ciphertext_multiply_cfg.dnum,
			true);
	std::ofstream("output/keyswitch.asm") << keyswitch_body;
	std::cout << "Saved keyswitch body ASM to output/keyswitch.asm\n";
	}
}

void test_relinearization_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string relinearization = generate_hpu_relinearization_asm(
			g_ciphertext_multiply_cfg.N,
			g_ciphertext_multiply_cfg.num_q,
			g_ciphertext_multiply_cfg.num_p,
			g_ciphertext_multiply_cfg.dnum,
			true);
		std::ofstream("output/relinearization.cpp") << relinearization;
		std::cout << "Saved relinearization ASM to output/relinearization.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string relinearization_body = generate_hpu_relinearization_body_asm(
			g_ciphertext_multiply_cfg.N,
			g_ciphertext_multiply_cfg.num_q,
			g_ciphertext_multiply_cfg.num_p,
			g_ciphertext_multiply_cfg.dnum,
			true);
		std::ofstream("output/relinearization.asm") << relinearization_body;
		std::cout << "Saved relinearization body ASM to output/relinearization.asm\n";
	}
}

void test_ciphertext_multiply_codegen()
{
	if (g_output_mode == OutputMode::CPP || g_output_mode == OutputMode::BOTH) {
		std::string ciphertext_multiply = generate_hpu_ciphertext_multiply_asm(
		g_ciphertext_multiply_cfg.N,
		g_ciphertext_multiply_cfg.num_q,
		g_ciphertext_multiply_cfg.num_p,
		g_ciphertext_multiply_cfg.dnum,
		true);
	std::ofstream("output/ciphertext_multiply.cpp") << ciphertext_multiply;
	std::cout << "Saved ciphertext_multiply ASM to output/ciphertext_multiply.cpp\n";
	}

	if (g_output_mode == OutputMode::ASM || g_output_mode == OutputMode::BOTH) {
		std::string ciphertext_multiply_body = generate_hpu_ciphertext_multiply_body_asm(
		g_ciphertext_multiply_cfg.N,
		g_ciphertext_multiply_cfg.num_q,
		g_ciphertext_multiply_cfg.num_p,
		g_ciphertext_multiply_cfg.dnum,
		true);
	std::ofstream("output/ciphertext_multiply.asm") << ciphertext_multiply_body;
	std::cout << "Saved ciphertext_multiply body ASM to output/ciphertext_multiply.asm\n";
	}
}

} // namespace

int main(int argc, char* argv[])
{
	try {
		std::string mode = "both";
		bool mode_seen = false;
		std::filesystem::path config_path = hpu::test::default_fhe_test_config_path();
		for (int index = 1; index < argc; ++index) {
			const std::string argument = argv[index];
			if (argument == "--config") {
				if (++index >= argc) {
					throw std::runtime_error("--config requires a path");
				}
				config_path = argv[index];
			} else if (!mode_seen
				&& (argument == "cpp" || argument == "asm" || argument == "both")) {
				mode = argument;
				mode_seen = true;
			} else {
				throw std::runtime_error("unknown argument: " + argument);
			}
		}

		if (mode == "cpp") {
			g_output_mode = OutputMode::CPP;
		} else if (mode == "asm") {
			g_output_mode = OutputMode::ASM;
		} else {
			g_output_mode = OutputMode::BOTH;
		}

		const hpu::test::FheTestConfig config =
			hpu::test::load_fhe_test_config(config_path);
		configure_generators(config);
		std::cout << "Loaded shared FHE config from " << config_path
			<< " (N=" << config.N << ", Q=" << config.num_q
			<< ", P=" << config.num_p << ", B=" << config.bfv_num_b
			<< ", dnum=" << config.dnum
			<< ", HPU_MEM_MAX=" << config.hpu_mem_max_lines << ")\n";

		std::filesystem::create_directory("output");
		std::filesystem::remove("output/rescale.asm");
		std::filesystem::remove("output/rescale.cpp");
		std::filesystem::remove("output/encode.asm");
		std::filesystem::remove("output/encode.cpp");
		std::filesystem::remove("output/bfv_behz_multiply.asm");
		std::filesystem::remove("output/bfv_behz_multiply.cpp");
		std::filesystem::remove("output/bfv_relinearization.asm");
		std::filesystem::remove("output/bfv_relinearization.cpp");
		for (const char* scheme : {"ckks", "bgv", "bfv"}) {
			std::filesystem::remove(
				std::filesystem::path("output") / (std::string(scheme) + "_encode.asm"));
			std::filesystem::remove(
				std::filesystem::path("output") / (std::string(scheme) + "_encode.cpp"));
		}
		test_ntt_codegen();
		test_intt_codegen();
		test_ckks_rescale_codegen();
		test_mm_codegen();
		test_bconv_codegen();
		test_pmult_codegen();
		test_cmult_codegen();
		test_modup_codegen();
		test_moddown_codegen();
		test_auto_codegen();
		test_ckks_rotate_codegen();
		test_ckks_standalone_ntt_kernels_codegen();
		test_ckks_pointwise_codegen();
		test_keyswitch_codegen();
		test_relinearization_codegen();
		test_ciphertext_multiply_codegen();
		test_ckks_ciphertext_multiply_codegen();
		test_bgv_ciphertext_multiply_codegen();
		test_bgv_modswitch_codegen();
		test_bfv_ciphertext_multiply_codegen();
		test_bfv_modswitch_codegen();
		return 0;
	} catch (const std::exception& exception) {
		std::cerr << "Instruction generation failed: " << exception.what() << '\n';
		return 1;
	}
}
