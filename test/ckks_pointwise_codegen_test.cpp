#include "scheme/ckks/basic_arithmetic.hpp"

#include <cmath>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

std::size_t count(const std::string& text, const std::string& needle)
{
    std::size_t result = 0;
    std::size_t position = 0;
    while ((position = text.find(needle, position)) != std::string::npos) {
        ++result;
        position += needle.size();
    }
    return result;
}

void require_common_shape(
    const std::string& program,
    int arithmetic_count,
    const std::string& arithmetic)
{
    if (program.find("Invalid CKKS") != std::string::npos) {
        throw std::runtime_error("valid pointwise configuration was rejected");
    }
    if (program.find("pntt ") != std::string::npos
        || program.find("pintt ") != std::string::npos) {
        throw std::runtime_error("pointwise CKKS kernel emitted an NTT transform");
    }
    if (count(program, arithmetic) != static_cast<std::size_t>(arithmetic_count)) {
        throw std::runtime_error("unexpected pointwise arithmetic instruction count");
    }
    if (count(program, "dload x10, x11, p4, 2, 1") != 1
        || count(program, "pfree p4") != 1
        || count(program, "psync") != 1) {
        throw std::runtime_error("modulus-table or terminal synchronization lifecycle failed");
    }
    const auto last_store = program.rfind("dstore ");
    const auto table_free = program.rfind("pfree p4");
    const auto sync = program.rfind("psync");
    if (last_store == std::string::npos || table_free <= last_store || sync <= table_free) {
        throw std::runtime_error("result must be stored before table release and psync");
    }
}

} // namespace

int main()
{
    try {
        constexpr int num_q = 4;
        const auto add = hpu::scheme::ckks::generate_add_body_asm(num_q, true);
        const auto subtract =
            hpu::scheme::ckks::generate_subtract_body_asm(num_q, true);
        const auto multiply_plain =
            hpu::scheme::ckks::generate_multiply_plain_body_asm(num_q, true);
        const auto add_plain =
            hpu::scheme::ckks::generate_add_plain_body_asm(num_q, true);
        const auto subtract_plain =
            hpu::scheme::ckks::generate_subtract_plain_body_asm(num_q, true);

        require_common_shape(add, 2 * num_q, "padd ");
        require_common_shape(subtract, 2 * num_q, "psub ");
        require_common_shape(multiply_plain, 2 * num_q, "pmul ");
        require_common_shape(add_plain, num_q, "padd ");
        require_common_shape(subtract_plain, num_q, "psub ");

        if (count(add, "dstore ") != 2 * num_q
            || count(subtract, "dstore ") != 2 * num_q
            || count(multiply_plain, "dstore ") != 2 * num_q
            || count(add_plain, "dstore ") != 2 * num_q
            || count(subtract_plain, "dstore ") != 2 * num_q) {
            throw std::runtime_error("pointwise kernel did not materialize two components");
        }

        const std::string nested_programs[] {
            hpu::scheme::ckks::generate_add_body_asm(num_q, false, false),
            hpu::scheme::ckks::generate_subtract_body_asm(num_q, false, false),
            hpu::scheme::ckks::generate_multiply_plain_body_asm(
                num_q, false, false),
            hpu::scheme::ckks::generate_add_plain_body_asm(
                num_q, false, false),
            hpu::scheme::ckks::generate_subtract_plain_body_asm(
                num_q, false, false),
        };
        for (const auto& nested : nested_programs) {
            if (nested.find("dload x10, x11, p4, 2, 1") != std::string::npos
                || nested.find("pfree p4") != std::string::npos
                || nested.find("psync") != std::string::npos) {
                throw std::runtime_error(
                    "nested pointwise body managed application-lifetime state");
            }
        }

        const double scale = std::pow(2.0, 40);
        if (!hpu::scheme::ckks::compatible_add_scales(scale, scale)
            || hpu::scheme::ckks::compatible_add_scales(scale, scale * 2.0)
            || hpu::scheme::ckks::compatible_add_scales(-1.0, scale)
            || hpu::scheme::ckks::multiply_plain_scale(scale, 8.0)
                != scale * 8.0) {
            throw std::runtime_error("CKKS pointwise scale policy failed");
        }

        std::cout << "CKKS pointwise Add/Sub/Plain codegen passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS pointwise codegen test failed: " << error.what() << '\n';
        return 1;
    }
}
