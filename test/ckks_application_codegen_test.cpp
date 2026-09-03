#include "scheme/ckks/ciphertext_multiply.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"

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
        constexpr std::size_t log_degree = 7;

        const std::string program =
            hpu::scheme::ckks::generate_ciphertext_multiply_body_asm(
                degree, num_q, num_p, dnum, true);

        require(
            count(program, hpu::dload(
                4, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank)) == 1,
            "application must load the complete modulus table exactly once");
        require(count(program, hpu::pfree(4)) == 1,
                "application must release the modulus table exactly once");
        require(count(program, hpu::psync()) == 1,
                "application must contain exactly one terminal psync");
        require(program.rfind(hpu::psync()) + hpu::psync().size() == program.size(),
                "psync must be the final instruction");
        const std::size_t last_store = program.rfind("\"dstore ");
        const std::size_t table_release = program.rfind(hpu::pfree(4));
        const std::size_t synchronization = program.rfind(hpu::psync());
        require(last_store != std::string::npos
                    && last_store < table_release
                    && table_release < synchronization,
                "final result must be dstore'd before table release and psync");
        require(program.find("no input NTT is emitted") != std::string::npos,
                "application does not declare the canonical NTT input contract");
        const std::size_t key_switch_ntt =
            program.find("Step 2: NTT on Q and P bases");
        require(key_switch_ntt != std::string::npos
                    && program.find("\"pntt ") >= key_switch_ntt,
                "a forward NTT was emitted before KeySwitch");

        // KeySwitch requires dnum transforms over Q union P. The only other
        // forward transforms are the two post-rescale outputs over Q\{q_last}.
        const std::size_t expected_pntt =
            (dnum * (num_q + num_p) + 2 * (num_q - 1)) * log_degree;
        // Three tensor components cross to coefficients, then the two Q/P
        // KeySwitch accumulators cross to coefficients before ModDown.
        const std::size_t expected_pintt =
            (3 * num_q + 2 * (num_q + num_p)) * log_degree;
        require(count(program, "\"pntt ") == expected_pntt,
                "application emitted a redundant or missing forward NTT");
        require(count(program, "\"pintt ") == expected_pintt,
                "application emitted a redundant or missing inverse NTT");

        // A larger application owns the small-bank table and final psync.
        // Nested bodies must be composable without reloading/releasing it.
        std::string polynomial_program = hpu::dload(
            4, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        polynomial_program +=
            hpu::scheme::ckks::generate_ciphertext_multiply_body_asm(
                degree, num_q, num_p, dnum, false, false);
        polynomial_program += hpu::scheme::ckks::generate_add_plain_body_asm(
            num_q - 1, false, false);
        polynomial_program += hpu::pfree(4);
        polynomial_program += hpu::psync();
        require(
            count(polynomial_program, hpu::dload(
                4, hpu::DataType::mod_ctx,
                hpu::DloadFlag::small_bank)) == 1
                && count(polynomial_program, hpu::pfree(4)) == 1
                && count(polynomial_program, hpu::psync()) == 1,
            "composed polynomial program duplicated application-lifetime state");

        std::cout << "CKKS application codegen lifecycle/transform tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS application codegen test failed: " << error.what() << '\n';
        return 1;
    }
}
