#pragma once

#include <cstdint>
#include <string>

std::string generate_hpu_auto_body_asm(
	int N,
	int num_q,
	int num_p,
	int dnum,
	std::uint64_t galois_element,
	bool append_psync = false);

std::string generate_hpu_auto_asm(
	int N,
	int num_q,
	int num_p,
	int dnum,
	std::uint64_t galois_element,
	bool append_psync = true);
