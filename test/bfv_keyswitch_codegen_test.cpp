#include "operator/keyswitch.hpp"
#include "operator/relinearization.hpp"
#include "operator/rns_layout.hpp"
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

hpu::RnsDecompositionLayout seal_bfv_layout()
{
    hpu::RnsDecompositionLayout layout;
    layout.q_mod_ids = {0, 1, 2};
    layout.p_mod_ids = {4};
    layout.key_digits = {{0}, {1}, {2}};
    return layout;
}

} // namespace

int main()
{
    try {
        constexpr int degree = 128;
        constexpr std::size_t log_degree = 7;
        const auto layout = seal_bfv_layout();

        require(hpu::is_seal_single_p_rns_decomposition_layout(degree, layout),
                "valid SEAL BFV layout was rejected");

        const std::string keyswitch = generate_hpu_bfv_keyswitch_body_asm(
            degree, layout, true);
        require(keyswitch.find("BFV KEYSWITCH BODY") != std::string::npos,
                "BFV KeySwitch marker is missing");
        require(keyswitch.find("BFV rounded coefficient-domain ModDown")
                    != std::string::npos
                    && keyswitch.find("ROUNDED SINGLE-P MODDOWN")
                        != std::string::npos,
                "BFV KeySwitch omitted rounded single-P finalization");
        require(keyswitch.find(hpu::pmodld(4)) != std::string::npos
                    && keyswitch.find(hpu::pmodld(3)) == std::string::npos,
                "BFV KeySwitch did not preserve the fixed P MOD_ID");
        require(count(keyswitch, "--- Digit ") == layout.q_mod_ids.size(),
                "BFV KeySwitch did not emit one digit per active Q limb");
        require(count(keyswitch, "\"pntt ")
                    == layout.key_digits.size()
                        * (layout.q_mod_ids.size() + 1) * log_degree,
                "BFV KeySwitch forward-transform count is wrong");
        require(count(keyswitch, "\"pintt ")
                    == 2 * (layout.q_mod_ids.size() + 1) * log_degree,
                "BFV KeySwitch inverse-transform count is wrong");
        require(count(keyswitch, hpu::padd(0, 0, 1))
                    == 2 * (layout.q_mod_ids.size() + 1),
                "BFV KeySwitch half-P addition count is wrong");
        require(count(keyswitch, hpu::psync()) == 1,
                "BFV KeySwitch needs one terminal psync");

        const std::size_t ntt = keyswitch.find("Step 2: NTT");
        const std::size_t intt = keyswitch.find("Step 4: INTT");
        const std::size_t rounded = keyswitch.find(
            "Step 5: BFV rounded coefficient-domain ModDown");
        const std::size_t merge = keyswitch.find(
            "Step 6: Add base component");
        require(ntt < intt && intt < rounded && rounded < merge,
                "BFV KeySwitch phase order is wrong");

        const std::string relinearization =
            generate_hpu_bfv_relinearization_body_asm(
                degree, layout, true);
        require(relinearization.find("BFV Relinearization")
                    != std::string::npos
                    && relinearization.find("out1 = t1 + ks1")
                        != std::string::npos
                    && count(relinearization, hpu::psync()) == 1,
                "BFV Relinearization did not compose the rounded KeySwitch");

        auto grouped = layout;
        grouped.key_digits = {{0, 1}, {2}};
        require(!hpu::is_seal_single_p_rns_decomposition_layout(
                    degree, grouped)
                    && generate_hpu_bfv_keyswitch_body_asm(
                           degree, grouped, false)
                           .find("Invalid SEAL BFV KeySwitch layout")
                        != std::string::npos,
                "grouped non-SEAL BFV key digits were accepted");

        auto multiple_p = layout;
        multiple_p.p_mod_ids = {4, 5};
        require(!hpu::is_seal_single_p_rns_decomposition_layout(
                    degree, multiple_p),
                "multi-P BFV layout was accepted as SEAL 4.4 compatible");

        const std::string generic = generate_hpu_keyswitch_body_asm(
            degree, layout, false);
        require(generic.find("ROUNDED SINGLE-P MODDOWN") == std::string::npos,
                "generic/CKKS KeySwitch semantics changed unexpectedly");

        std::cout << "BFV SEAL-layout rounded KeySwitch/Relinearization codegen tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BFV KeySwitch codegen test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
