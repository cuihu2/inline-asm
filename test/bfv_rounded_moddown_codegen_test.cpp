#include "operator/rounded_drop_last.hpp"
#include "util/hpu_asm.hpp"

#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

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
        const std::vector<int> q_contexts{0, 1, 2};
        constexpr int p_context = 4;
        constexpr int components = 2;

        const std::string program =
            generate_hpu_rounded_single_p_moddown_contexts_body_asm(
                q_contexts, p_context, components, true);
        require(program.find("ROUNDED SINGLE-P MODDOWN") != std::string::npos,
                "rounded single-P ModDown marker is missing");
        require(program.find("No coefficient comparison") != std::string::npos,
                "comparison-free rounding contract is missing");
        require(program.find(hpu::pmodld(p_context)) != std::string::npos,
                "fixed special-P MOD_ID is missing");
        require(program.find(hpu::pmodld(3)) == std::string::npos,
                "rounded ModDown incorrectly assumed that P follows active Q");
        require(count(program, hpu::padd(0, 0, 1))
                    == components * (q_contexts.size() + 1),
                "half-P addition count is wrong");
        require(count(program, hpu::psync()) == 1,
                "complete rounded ModDown needs one terminal psync");

        const std::size_t rounding = program.find("stage-1: add floor(P/2)");
        const std::size_t conversion = program.find("MODDOWN stage-1: BConv P -> Q");
        const std::size_t divide = program.find("MODDOWN stage-2: q <- q - correction");
        require(rounding != std::string::npos
                    && conversion != std::string::npos
                    && divide != std::string::npos
                    && rounding < conversion && conversion < divide,
                "rounded ModDown phase order is wrong");

        const std::string nested =
            generate_hpu_rounded_single_p_moddown_contexts_body_asm(
                q_contexts, p_context, 1, false, false);
        require(nested.find(hpu::dload(
                    4, hpu::DataType::mod_ctx,
                    hpu::DloadFlag::small_bank)) == std::string::npos
                    && nested.find(hpu::pfree(4)) == std::string::npos
                    && nested.find(hpu::psync()) == std::string::npos,
                "nested rounded ModDown duplicated application-owned state");

        const std::string invalid =
            generate_hpu_rounded_single_p_moddown_contexts_body_asm(
                q_contexts, 2, 1);
        require(invalid.find("Invalid rounded single-P ModDown")
                    != std::string::npos,
                "overlapping Q/P layout was accepted");

        const std::string drop_last =
            generate_hpu_rounded_drop_last_body_asm(4, 2, true);
        require(drop_last.find("ROUNDED DROP-LAST") != std::string::npos
                    && drop_last.find("ROUNDED SINGLE-P MODDOWN")
                        != std::string::npos
                    && count(drop_last, hpu::psync()) == 1,
                "legacy rounded drop-last did not reuse the explicit primitive");

        std::cout << "BFV rounded coefficient-domain ModDown codegen tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BFV rounded ModDown codegen test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
