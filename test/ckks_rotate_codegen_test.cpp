#include "scheme/ckks/rotate.hpp"
#include "scheme/ckks/galois.hpp"

#include "util/hpu_asm.hpp"

#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

std::size_t count(const std::string& text, const std::string& token)
{
    std::size_t result = 0;
    std::size_t position = 0;
    while ((position = text.find(token, position)) != std::string::npos) {
        ++result;
        position += token.size();
    }
    return result;
}

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

} // namespace

int main()
{
    try {
        constexpr int degree = 128;
        constexpr int num_q = 4;
        constexpr int num_p = 1;
        constexpr int dnum = 4;
        constexpr std::uint32_t galois_element = 3;
        constexpr std::size_t log_degree = 7;

        require(
            hpu::scheme::ckks::rotation_galois_element(degree, 1) == 3
                && hpu::scheme::ckks::rotation_galois_element(degree, 2) == 9
                && hpu::scheme::ckks::rotation_galois_element(degree, -1)
                    == 171
                && hpu::scheme::ckks::conjugation_galois_element(degree)
                    == 255,
            "slot-step to Galois-element mapping differs from SEAL");

        const std::string program = hpu::scheme::ckks::generate_rotate_body_asm(
            degree, num_q, num_p, dnum, galois_element, true);
        require(program.find("INTT_psi^(1/k)") != std::string::npos,
                "Rotate does not select the fused modified-root INTT path");
        require(program.find("no coefficient permutation") != std::string::npos,
                "Rotate still depends on a CPU coefficient permutation");
        require(count(program, hpu::dload(
                    4, hpu::DataType::mod_ctx,
                    hpu::DloadFlag::small_bank)) == 1,
                "Rotate must load the modulus table once");
        require(count(program, hpu::pfree(4)) == 1,
                "Rotate must release the modulus table once");
        require(count(program, hpu::psync()) == 1,
                "Rotate must have one terminal psync");
        require(program.rfind(hpu::psync()) + hpu::psync().size() == program.size(),
                "Rotate psync is not terminal");
        require(program.rfind("\"dstore ") < program.rfind(hpu::pfree(4))
                    && program.rfind(hpu::pfree(4)) < program.rfind(hpu::psync()),
                "Rotate must dstore final outputs before release and psync");

        // Fused INTT: 2Q. KeySwitch: dnum*(Q+P) NTT and 2*(Q+P)
        // INTT. The only final transforms are the two canonical Q outputs.
        const std::size_t expected_pntt =
            (dnum * (num_q + num_p) + 2 * num_q) * log_degree;
        const std::size_t expected_pintt =
            (2 * num_q + 2 * (num_q + num_p)) * log_degree;
        require(count(program, "\"pntt ") == expected_pntt,
                "Rotate emitted a redundant or missing forward NTT");
        require(count(program, "\"pintt ") == expected_pintt,
                "Rotate emitted a redundant or missing inverse NTT");

        const std::size_t fused = program.find("FUSED AUTO");
        const std::size_t key_switch = program.find("--- Galois KeySwitch:");
        const std::size_t output_ntt = program.find("Canonical output NTT");
        require(fused != std::string::npos
                    && key_switch != std::string::npos
                    && output_ntt != std::string::npos
                    && fused < key_switch
                    && key_switch < output_ntt,
                "Rotate phase order is not fused INTT -> KeySwitch -> output NTT");

        const auto rotate_left_two =
            hpu::scheme::ckks::generate_rotate_steps_body_asm(
                degree, num_q, num_p, dnum, 2, true);
        const auto rotate_right_one =
            hpu::scheme::ckks::generate_rotate_steps_body_asm(
                degree, num_q, num_p, dnum, -1, true);
        const auto conjugate =
            hpu::scheme::ckks::generate_conjugate_body_asm(
                degree, num_q, num_p, dnum, true);
        require(rotate_left_two.find("steps=2, Galois element=9")
                    != std::string::npos
                    && rotate_right_one.find("steps=-1, Galois element=171")
                        != std::string::npos
                    && conjugate.find("CKKS CONJUGATE: Galois element=255")
                        != std::string::npos,
                "high-level Rotate/Conjugate did not select the expected element");
        require(count(rotate_left_two, "FUSED AUTO") == 1
                    && count(rotate_right_one, "FUSED AUTO") == 1
                    && count(conjugate, "FUSED AUTO") == 1,
                "high-level Galois operations did not reuse fused Rotate");
        require(
            hpu::scheme::ckks::generate_rotate_steps_body_asm(
                degree, num_q, num_p, dnum, 0, true)
                    .find("Invalid CKKS") != std::string::npos,
            "zero-step Rotate should remain a host no-op");

        std::cout
            << "CKKS fused raw/slot-step Rotate and Conjugate codegen tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS Rotate codegen test failed: " << error.what() << '\n';
        return 1;
    }
}
