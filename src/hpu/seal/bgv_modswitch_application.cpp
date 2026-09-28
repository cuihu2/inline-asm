#include "hpu/seal/bgv_modswitch_application.hpp"

#include "hpu/model/hardware_ntt.hpp"
#include "hpu/seal/ntt_bridge.hpp"
#include "scheme/bgv/modswitch.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include "assembler.hpp"
#include "executable.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::uint32_t narrow(std::uint64_t value)
{
    if (value < 65537 || value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("BGV modulus is outside the HPU PE range");
    }
    return static_cast<std::uint32_t>(value);
}

std::uint64_t barrett_mu(std::uint32_t modulus)
{
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(1) << 64) / modulus);
}

std::size_t bit_reverse(std::size_t value, std::size_t degree)
{
    std::size_t result = 0;
    for (std::size_t width = degree; width > 1; width >>= 1U) {
        result = (result << 1U) | (value & 1U);
        value >>= 1U;
    }
    return result;
}

std::string mod_id(const std::string& prefix, int id)
{
    return prefix + "/mod" + std::to_string(id);
}

std::string stage_id(const std::string& prefix, std::size_t stage)
{
    return prefix + "/stage" + std::to_string(stage);
}

std::vector<std::uint32_t> splat(std::size_t degree, std::uint32_t value)
{
    return std::vector<std::uint32_t>(degree, value);
}

std::size_t ntt_stage_count(std::size_t degree)
{
    std::size_t result = 0;
    for (std::size_t remaining = degree; remaining > 1; remaining >>= 1U) {
        ++result;
    }
    return result;
}

void add_twiddles(hpu::runtime::HpuMemImage& image, std::size_t degree,
                  int modulus_id, std::uint32_t modulus, std::uint32_t psi)
{
    const std::string prefix = mod_id("constants/twiddle/canonical", modulus_id);
    hpu::model::HardwareNttModel model(
        degree, modulus, hpu::model::pow_mod(psi, 2, modulus));
    std::vector<std::uint32_t> pre_twist(degree);
    for (std::size_t index = 0; index < degree; ++index) {
        pre_twist[index] = hpu::model::pow_mod(
            psi, bit_reverse(index, degree), modulus);
    }
    image.add(prefix + "/ntt/pre_twist", pre_twist,
              hpu::runtime::AllocationKind::twiddle);
    const auto forward = model.forward_twiddles();
    for (std::size_t stage = 0; stage < forward.size(); ++stage) {
        image.add(stage_id(prefix + "/ntt", stage), forward[stage],
                  hpu::runtime::AllocationKind::twiddle);
    }
    const auto inverse = model.inverse_twiddles();
    for (std::size_t stage = 0; stage < inverse.stages.size(); ++stage) {
        image.add(stage_id(prefix + "/intt", stage), inverse.stages[stage],
                  hpu::runtime::AllocationKind::twiddle);
    }
    const std::uint32_t inverse_psi = hpu::model::inverse_mod_prime(psi, modulus);
    std::vector<std::uint32_t> post(degree);
    for (std::size_t index = 0; index < degree; ++index) {
        const std::uint32_t untwist = hpu::model::pow_mod(
            inverse_psi, bit_reverse(index, degree), modulus);
        post[index] = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(inverse.post_scale[index]) * untwist) % modulus);
    }
    image.add(prefix + "/intt/post_untwist_scale", post,
              hpu::runtime::AllocationKind::twiddle);
}

class DmaRecipe {
public:
    DmaRecipe(const hpu::runtime::HpuMemImage& image,
              const std::vector<hpu::DmaRelocation>& encoded)
        : image_(image), encoded_(encoded)
    {}

    void load(int slot, const std::string& id, std::size_t words,
              hpu::DataType type = hpu::DataType::poly,
              hpu::DloadFlag flag = hpu::DloadFlag::regular_bank)
    {
        bind(id, words, hpu::Mnemonic::kDload, slot,
             static_cast<std::uint8_t>(type), static_cast<std::uint8_t>(flag));
    }

    void store(int slot, const std::string& id, std::size_t words)
    {
        bind(id, words, hpu::Mnemonic::kDstore, slot, 1, 0);
    }

    std::vector<BgvModSwitchDmaBinding> finish()
    {
        if (bindings_.size() != encoded_.size()) {
            throw std::logic_error("BGV ModSwitch DMA recipe did not consume every instruction");
        }
        return std::move(bindings_);
    }

private:
    void bind(const std::string& id, std::size_t words, hpu::Mnemonic direction,
              int slot, std::uint8_t type_or_release, std::uint8_t flag)
    {
        const std::size_t index = bindings_.size();
        if (index >= encoded_.size()) {
            throw std::logic_error("BGV ModSwitch DMA recipe exceeds encoded stream");
        }
        const auto& instruction = encoded_[index];
        const auto& allocation = image_.allocation(id);
        if (instruction.dma_index != index || instruction.direction != direction ||
            instruction.object_id != slot ||
            instruction.type_or_release != type_or_release ||
            (direction == hpu::Mnemonic::kDload && instruction.flag != flag) ||
            allocation.word_count != words || allocation.span.line_count == 0 ||
            (direction == hpu::Mnemonic::kDstore && allocation.read_only)) {
            throw std::invalid_argument(
                "BGV ModSwitch DMA binding disagrees with encoded instruction or image: " + id);
        }
        bindings_.push_back({
            index, instruction.instruction_index, instruction.direction,
            instruction.object_id, instruction.type_or_release,
            instruction.flag, id, allocation.span});
    }

    const hpu::runtime::HpuMemImage& image_;
    const std::vector<hpu::DmaRelocation>& encoded_;
    std::vector<BgvModSwitchDmaBinding> bindings_;
};

std::string csv_field(const std::string& value)
{
    std::string result = "\"";
    for (char character : value) {
        if (character == '"') {
            result += '"';
        }
        result += character;
    }
    return result + '"';
}

} // namespace

std::vector<hpu::runtime::HpuMemSpan> BgvModSwitchApplication::spans() const
{
    std::vector<hpu::runtime::HpuMemSpan> result;
    result.reserve(dma.size());
    for (const auto& binding : dma) {
        result.push_back(binding.span);
    }
    return result;
}

BgvModSwitchApplication build_bgv_modswitch_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& input,
    std::uint64_t capacity_lines)
{
    const auto key_data = context.key_context_data();
    const auto first_data = context.first_context_data();
    const auto source = context.get_context_data(input.parms_id());
    if (!context.parameters_set() || !key_data || !first_data || !source ||
        !source->next_context_data() ||
        key_data->parms().scheme() != ::seal::scheme_type::bgv ||
        !::seal::is_valid_for(input, context) || !input.is_ntt_form() ||
        input.size() < 2) {
        throw std::invalid_argument("BGV ModSwitch requires a valid NTT ciphertext with a next level");
    }
    const std::size_t degree = source->parms().poly_modulus_degree();
    const auto& key_moduli = key_data->parms().coeff_modulus();
    const auto& top_moduli = first_data->parms().coeff_modulus();
    const auto& source_moduli = source->parms().coeff_modulus();
    const auto& destination_moduli =
        source->next_context_data()->parms().coeff_modulus();
    if (key_moduli.size() != top_moduli.size() + 1 ||
        key_moduli.size() + 1 > static_cast<std::size_t>(hpu::kMaxModContexts) ||
        source_moduli.size() < 2 ||
        destination_moduli.size() + 1 != source_moduli.size() ||
        source_moduli.size() > top_moduli.size() ||
        degree > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        !hpu::is_valid_ntt_size(static_cast<int>(degree))) {
        throw std::invalid_argument("unsupported BGV Qmax|P|t level layout");
    }
    std::vector<std::uint32_t> q_moduli;
    for (std::size_t index = 0; index < source_moduli.size(); ++index) {
        if (source_moduli[index].value() != key_moduli[index].value() ||
            (index < destination_moduli.size() &&
             destination_moduli[index].value() != source_moduli[index].value())) {
            throw std::invalid_argument("BGV active Q is not a drop-last key-context prefix");
        }
        q_moduli.push_back(narrow(source_moduli[index].value()));
    }
    const std::uint32_t t = narrow(source->parms().plain_modulus().value());
    const auto constants = hpu::scheme::bgv::prepare_ntt_modswitch_constants(q_moduli, t);
    const int t_id = static_cast<int>(key_moduli.size());
    hpu::scheme::bgv::NttModSwitchLayout layout;
    layout.plaintext_mod_id = t_id;
    for (std::size_t index = 0; index < q_moduli.size(); ++index) {
        layout.q_mod_ids.push_back(static_cast<int>(index));
    }

    hpu::runtime::HpuMemImage image(capacity_lines);
    std::vector<std::uint32_t> modulus_words;
    for (const auto& modulus : key_moduli) {
        const std::uint32_t value = narrow(modulus.value());
        const std::uint64_t mu = barrett_mu(value);
        modulus_words.insert(modulus_words.end(), {
            value, static_cast<std::uint32_t>(mu),
            static_cast<std::uint32_t>(mu >> 32U), 0});
    }
    const std::uint64_t t_mu = barrett_mu(t);
    modulus_words.insert(modulus_words.end(), {
        t, static_cast<std::uint32_t>(t_mu),
        static_cast<std::uint32_t>(t_mu >> 32U), 0});
    image.add("constants/modulus_table", modulus_words,
              hpu::runtime::AllocationKind::modulus_table);
    const auto* seal_tables = source->small_ntt_tables();
    for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
        add_twiddles(image, degree, static_cast<int>(basis), q_moduli[basis],
                     static_cast<std::uint32_t>(seal_tables[basis].get_root()));
    }
    const std::string constant_prefix = "constants/bgv_modswitch";
    image.add(constant_prefix + "/neg_inv_t",
              splat(degree, constants.neg_q_last_inverse_mod_t),
              hpu::runtime::AllocationKind::constant);
    for (std::size_t basis = 0; basis + 1 < q_moduli.size(); ++basis) {
        const int id = static_cast<int>(basis);
        image.add(mod_id(constant_prefix + "/q_last_mod", id),
                  splat(degree, constants.q_last_mod_q[basis]),
                  hpu::runtime::AllocationKind::constant);
        image.add(mod_id(constant_prefix + "/q_last_inv", id),
                  splat(degree, constants.q_last_inverse_mod_q[basis]),
                  hpu::runtime::AllocationKind::constant);
    }
    for (std::size_t component = 0; component < input.size(); ++component) {
        const auto prepared = ciphertext_component_to_hpu(input, component, context);
        for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
            const auto first = prepared.words.begin() +
                static_cast<std::ptrdiff_t>(basis * degree);
            image.add(mod_id("input/c" + std::to_string(component), static_cast<int>(basis)),
                      std::vector<std::uint32_t>(first, first + degree),
                      hpu::runtime::AllocationKind::ciphertext);
        }
        image.reserve("workspace/bgv_modswitch/c" + std::to_string(component) + "/last_coeff",
                      degree, hpu::runtime::AllocationKind::workspace);
        image.reserve("workspace/bgv_modswitch/c" + std::to_string(component) + "/u_t",
                      degree, hpu::runtime::AllocationKind::workspace);
        for (std::size_t basis = 0; basis + 1 < q_moduli.size(); ++basis) {
            image.reserve(mod_id("output/c" + std::to_string(component), static_cast<int>(basis)),
                          degree, hpu::runtime::AllocationKind::output);
        }
    }

    const auto body = hpu::scheme::bgv::generate_modswitch_ntt_body_asm(
        static_cast<int>(degree), layout, static_cast<int>(input.size()), true, true);
    auto instructions = hpu::assemble_source(body);
    hpu::validate_executable_program(instructions);
    const auto encoded_dma = hpu::collect_dma_relocations(instructions);
    DmaRecipe recipe(image, encoded_dma);
    const std::size_t stages = ntt_stage_count(degree);
    recipe.load(4, "constants/modulus_table", modulus_words.size(),
                hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    for (std::size_t component = 0; component < input.size(); ++component) {
        const std::string component_prefix = "c" + std::to_string(component);
        const int last_id = layout.q_mod_ids.back();
        const std::string twiddle_last = mod_id("constants/twiddle/canonical", last_id);
        const std::string last_coeff =
            "workspace/bgv_modswitch/" + component_prefix + "/last_coeff";
        const std::string u_t = "workspace/bgv_modswitch/" + component_prefix + "/u_t";
        recipe.load(0, mod_id("input/" + component_prefix, last_id), degree);
        for (std::size_t stage = 0; stage < stages; ++stage) {
            recipe.load(3, stage_id(twiddle_last + "/intt", stage), degree / 2);
        }
        recipe.load(3, twiddle_last + "/intt/post_untwist_scale", degree);
        recipe.store(0, last_coeff, degree);
        recipe.load(0, last_coeff, degree);
        recipe.load(1, constant_prefix + "/neg_inv_t", degree);
        recipe.store(0, u_t, degree);
        for (std::size_t basis = 0; basis + 1 < q_moduli.size(); ++basis) {
            const int id = static_cast<int>(basis);
            const std::string twiddle_q = mod_id("constants/twiddle/canonical", id);
            recipe.load(0, u_t, degree);
            recipe.load(1, mod_id(constant_prefix + "/q_last_mod", id), degree);
            recipe.load(1, last_coeff, degree);
            recipe.load(3, twiddle_q + "/ntt/pre_twist", degree);
            for (std::size_t stage = 0; stage < stages; ++stage) {
                recipe.load(3, stage_id(twiddle_q + "/ntt", stage), degree / 2);
            }
            recipe.load(1, mod_id("input/" + component_prefix, id), degree);
            recipe.load(0, mod_id(constant_prefix + "/q_last_inv", id), degree);
            recipe.store(1, mod_id("output/" + component_prefix, id), degree);
        }
    }

    auto bindings = recipe.finish();
    BgvModSwitchApplication result{
        std::move(image), input.parms_id(), source->next_context_data()->parms_id(),
        hpu::scheme::bgv::modswitch_correction_factor(
            input.correction_factor(), q_moduli.back(), t),
        std::move(instructions), std::move(bindings)};
    return result;
}

BgvModSwitchRuntimeArtifacts render_bgv_modswitch_runtime_artifacts(
    const std::string& stem, const BgvModSwitchApplication& application)
{
    if (application.image.capacity_lines() > std::numeric_limits<std::uint32_t>::max() ||
        application.dma.empty()) {
        throw std::invalid_argument("BGV ModSwitch runtime needs a nonempty uint32-addressable image");
    }
    const auto encoded = hpu::collect_dma_relocations(application.instructions);
    hpu::validate_executable_program(application.instructions);
    if (encoded.size() != application.dma.size()) {
        throw std::invalid_argument("BGV ModSwitch encoded DMA count differs from bindings");
    }
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        const auto& binding = application.dma[index];
        const auto& allocation = application.image.allocation(binding.allocation_id);
        if (binding.dma_index != index ||
            binding.instruction_index != encoded[index].instruction_index ||
            binding.direction != encoded[index].direction ||
            binding.object_slot != encoded[index].object_id ||
            binding.type_or_release != encoded[index].type_or_release ||
            binding.flag != encoded[index].flag ||
            binding.span.line_offset != allocation.span.line_offset ||
            binding.span.line_count != allocation.span.line_count ||
            binding.span.line_offset >= application.image.capacity_lines() ||
            binding.span.line_count > application.image.capacity_lines() - binding.span.line_offset) {
            throw std::invalid_argument("BGV ModSwitch runtime binding is unresolved or out of range");
        }
    }
    const std::string identifier = hpu::c_identifier(stem);
    BgvModSwitchRuntimeArtifacts result;
    result.header = hpu::render_executable_header(stem, application.dma.size());
    const std::string marker = "#ifdef __cplusplus\n}\n#endif\n\n#endif\n";
    const auto position = result.header.find(marker);
    if (position == std::string::npos) {
        throw std::logic_error("BGV ModSwitch executable header has unexpected structure");
    }
    result.header.insert(position, "int hpu_run_" + identifier + "(void);\n\n");
    result.source = hpu::render_executable_source(
        stem, application.instructions, application.image.capacity_lines());
    std::ostringstream source;
    source << "\nstatic const hpu_dma_span_t hpu_program_" << identifier
           << "_resolved_spans[] = {\n";
    for (const auto& binding : application.dma) {
        source << "    { UINT32_C(" << binding.span.line_offset << "), UINT32_C("
               << binding.span.line_count << ") },\n";
    }
    source << "};\n\nint hpu_run_" << identifier << "(void) {\n"
           << "    return hpu_program_" << identifier << "(\n"
           << "        hpu_program_" << identifier << "_resolved_spans,\n"
           << "        HPU_PROGRAM_";
    for (char character : identifier) {
        source << static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    }
    source << "_DMA_COUNT);\n}\n";
    result.source += source.str();

    std::ostringstream manifest;
    manifest << "instruction_index,dma_index,allocation_id,line_offset,line_count,word_hex\n";
    for (std::size_t index = 0; index < application.dma.size(); ++index) {
        const auto& binding = application.dma[index];
        manifest << binding.instruction_index << ',' << index << ','
                 << csv_field(binding.allocation_id) << ','
                 << binding.span.line_offset << ',' << binding.span.line_count << ','
                 << hpu::format_word_hex(
                        application.instructions[binding.instruction_index].word) << '\n';
    }
    result.resolved_dma_manifest = manifest.str();
    return result;
}

} // namespace hpu::seal_adapter
