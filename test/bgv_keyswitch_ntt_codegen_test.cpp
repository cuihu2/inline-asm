#include "assembler.hpp"
#include "executable.hpp"
#include "scheme/bgv/keyswitch.hpp"
#include "util/hpu_asm.hpp"

#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

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

hpu::RnsDecompositionLayout layout(int q_count)
{
    hpu::RnsDecompositionLayout result;
    for (int id = 0; id < q_count; ++id) {
        result.q_mod_ids.push_back(id);
        result.key_digits.push_back({id});
    }
    result.p_mod_ids = {4};
    return result;
}

void check(int degree, int q_count)
{
    constexpr int t_id = 5;
    const auto program = hpu::scheme::bgv::generate_keyswitch_ntt_body_asm(
        degree, layout(q_count), t_id, true, true);
    require(program.find("Invalid") == std::string::npos,
            "valid BGV NTT KeySwitch layout was rejected");
    const std::size_t stages = degree == 128 ? 7 : 16;
    const std::size_t q = static_cast<std::size_t>(q_count);
    require(count(program, "\"pintt ") == (q + 2) * stages,
            "BGV KeySwitch inversed more than the Q digits and two P accumulators");
    require(count(program, "\"pntt ") == (q * q + 2 * q) * stages,
            "BGV KeySwitch cross-base or correction NTT count is wrong");
    require(count(program, hpu::pmul_imm(0, 0, 1)) == q * q &&
                count(program, hpu::pmul_imm(1, 1, 1)) == 2 * q,
            "BGV KeySwitch did not normalize cross-base operands before NTT/PADD");
    require(count(program, hpu::pmodld(4)) >= 2 &&
                count(program, hpu::pmodld(t_id)) == 2,
            "BGV KeySwitch lost fixed special-P or plaintext MOD_ID");
    for (int inactive = q_count; inactive < 4; ++inactive) {
        require(program.find(hpu::pmodld(inactive)) == std::string::npos,
                "BGV KeySwitch selected a dropped Q MOD_ID");
    }
    require(count(program, hpu::dload(
                4, hpu::DataType::mod_ctx,
                hpu::DloadFlag::small_bank)) == 1 &&
                count(program, hpu::psync()) == 1,
            "complete BGV KeySwitch duplicated modulus table or psync");
    const auto encoded = hpu::assemble_source(program);
    hpu::validate_executable_program(encoded);
    require(!encoded.empty(), "BGV KeySwitch did not encode instructions");

    const auto nested = hpu::scheme::bgv::generate_keyswitch_ntt_body_asm(
        degree, layout(q_count), t_id);
    require(nested.find(hpu::dload(
                4, hpu::DataType::mod_ctx,
                hpu::DloadFlag::small_bank)) == std::string::npos &&
                nested.find(hpu::pfree(4)) == std::string::npos &&
                nested.find(hpu::psync()) == std::string::npos,
            "nested BGV KeySwitch duplicated application-owned state");
}

} // namespace

int main()
{
    try {
        check(128, 3);
        check(128, 2);
        check(65536, 3);
        require(hpu::scheme::bgv::generate_keyswitch_ntt_body_asm(
                    128, layout(3), 4).find("Invalid") != std::string::npos,
                "BGV KeySwitch accepted overlapping P/t MOD_IDs");
        std::cout << "BGV NTT KeySwitch codegen tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV NTT KeySwitch codegen test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
