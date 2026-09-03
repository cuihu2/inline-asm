#include "scheme/ckks/relinearize.hpp"
#include "scheme/ckks/rescale.hpp"

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

void check_lifecycle(const std::string& program, const char* role)
{
    if (count(program, hpu::dload(
            4, hpu::DataType::mod_ctx,
            hpu::DloadFlag::small_bank)) != 1
        || count(program, hpu::pfree(4)) != 1
        || count(program, hpu::psync()) != 1
        || program.rfind(hpu::psync()) + hpu::psync().size() != program.size()
        || program.rfind("\"dstore ") >= program.rfind(hpu::pfree(4))) {
        throw std::runtime_error(std::string(role) + " has an invalid application lifecycle");
    }
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

        const std::string relinearize =
            hpu::scheme::ckks::generate_relinearize_ntt_body_asm(
                degree, num_q, num_p, dnum, true);
        check_lifecycle(relinearize, "Relinearize");
        require(count(relinearize, "\"pntt ")
                    == (dnum * (num_q + num_p) + 2 * num_q) * log_degree,
                "standalone Relinearize forward-transform count is wrong");
        require(count(relinearize, "\"pintt ")
                    == (3 * num_q + 2 * (num_q + num_p)) * log_degree,
                "standalone Relinearize inverse-transform count is wrong");

        const std::string rescale =
            hpu::scheme::ckks::generate_rescale_ntt_body_asm(
                degree, num_q, true);
        check_lifecycle(rescale, "Rescale");
        require(count(rescale, "\"pntt ")
                    == 2 * (num_q - 1) * log_degree,
                "standalone Rescale forward-transform count is wrong");
        require(count(rescale, "\"pintt ") == 2 * num_q * log_degree,
                "standalone Rescale inverse-transform count is wrong");
        require(rescale.find("CKKS RESCALE NTT") != std::string::npos,
                "standalone SEAL-facing Rescale marker is missing");

        std::cout << "CKKS standalone Relinearize/Rescale codegen tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS standalone kernel test failed: " << error.what() << '\n';
        return 1;
    }
}
