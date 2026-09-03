#include "scheme/ckks/rotate.hpp"

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
        const std::size_t key_switch = program.find("Galois KeySwitch");
        const std::size_t output_ntt = program.find("Canonical output NTT");
        require(fused < key_switch && key_switch < output_ntt,
                "Rotate phase order is not fused INTT -> KeySwitch -> output NTT");

        std::cout << "CKKS fused Rotate codegen tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS Rotate codegen test failed: " << error.what() << '\n';
        return 1;
    }
}
