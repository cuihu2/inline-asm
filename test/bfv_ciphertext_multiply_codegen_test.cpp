#include "scheme/bfv/ciphertext_multiply.hpp"
#include "util/hpu_asm.hpp"

#include <cstddef>
#include <cstdint>
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

hpu::scheme::bfv::BfvCiphertextMultiplyLayout seal_layout()
{
    hpu::scheme::bfv::BfvCiphertextMultiplyLayout layout;
    layout.keyswitch_layout.q_mod_ids = {0, 1, 2};
    layout.keyswitch_layout.p_mod_ids = {4};
    layout.keyswitch_layout.key_digits = {{0}, {1}, {2}};
    layout.b_mod_ids = {6, 7, 8, 9};
    layout.m_sk_mod_id = 10;
    layout.plaintext_mod_id = 11;
    return layout;
}

} // namespace

int main()
{
    try {
        constexpr int degree = 128;
        constexpr std::uint64_t plaintext_modulus = 65537;
        const auto layout = seal_layout();
        require(hpu::scheme::bfv::is_valid_ciphertext_multiply_layout(degree, layout,
                                                                      plaintext_modulus),
                "valid explicit SEAL BFV multiply layout was rejected");

        const std::string program = hpu::scheme::bfv::generate_ciphertext_multiply_body_asm(
            degree, layout, plaintext_modulus, true, true);
        const std::string modulus_load =
            hpu::dload(4, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        require(program.find("BFV BEHZ MULTIPLY") != std::string::npos &&
                    program.find("BFV Relinearization") != std::string::npos &&
                    program.find("ROUNDED SINGLE-P MODDOWN") != std::string::npos,
                "explicit BFV multiply omitted BEHZ or rounded relinearization");
        require(count(program, modulus_load) == 1 && count(program, hpu::pfree(4)) == 1 &&
                    count(program, hpu::psync()) == 1 &&
                    program.rfind(hpu::psync()) + hpu::psync().size() == program.size(),
                "explicit BFV multiply does not own one table lifetime and terminal psync");
        require(program.find(hpu::pmodld(4)) != std::string::npos &&
                    program.find(hpu::pmodld(6)) != std::string::npos &&
                    program.find(hpu::pmodld(10)) != std::string::npos &&
                    program.find(hpu::pmodld(3)) == std::string::npos &&
                    program.find(hpu::pmodld(5)) == std::string::npos &&
                    program.find(hpu::pmodld(11)) == std::string::npos,
                "explicit BFV multiply renumbered or executed an inactive MOD_ID");

        const std::string nested = hpu::scheme::bfv::generate_ciphertext_multiply_body_asm(
            degree, layout, plaintext_modulus, false, false);
        require(nested.find(modulus_load) == std::string::npos &&
                    nested.find(hpu::pfree(4)) == std::string::npos &&
                    nested.find(hpu::psync()) == std::string::npos,
                "nested BFV multiply did not delegate table/sync ownership");

        auto duplicate = layout;
        duplicate.b_mod_ids.front() = duplicate.keyswitch_layout.p_mod_ids.front();
        require(!hpu::scheme::bfv::is_valid_ciphertext_multiply_layout(degree, duplicate,
                                                                       plaintext_modulus),
                "overlapping BFV multiply MOD_IDs were accepted");
        auto grouped = layout;
        grouped.keyswitch_layout.key_digits = {{0, 1}, {2}};
        require(!hpu::scheme::bfv::is_valid_ciphertext_multiply_layout(degree, grouped,
                                                                       plaintext_modulus),
                "non-SEAL BFV multiply digits were accepted");
        auto insufficient_b = layout;
        insufficient_b.b_mod_ids = {6, 7};
        require(!hpu::scheme::bfv::is_valid_ciphertext_multiply_layout(degree, insufficient_b,
                                                                       plaintext_modulus),
                "insufficient BFV auxiliary base was accepted");

        std::cout << "BFV explicit-layout ciphertext multiply codegen tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BFV ciphertext multiply codegen test failed: " << error.what() << '\n';
        return 1;
    }
}
