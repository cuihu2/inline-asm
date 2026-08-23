#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "assembler.hpp"
#include "executable.hpp"
#include "util/hpu_asm.hpp"

namespace {

void expect_rejected(const std::string& source)
{
    try {
        (void)hpu::assemble_line(source);
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("invalid instruction was accepted: " + source);
}

void expect_encoded(const std::string& source, std::uint32_t expected)
{
    const hpu::EncodedInstruction encoded = hpu::assemble_line(source);
    if (encoded.word != expected) {
        throw std::runtime_error("unexpected encoding for: " + source);
    }
}

void expect_precoded(const std::string& source,
                     std::uint32_t expected_word,
                     std::uint32_t expected_command26)
{
    const hpu::EncodedInstruction encoded = hpu::assemble_line(source);
    if (encoded.word != expected_word || encoded.command26 != expected_command26) {
        throw std::runtime_error("unexpected instruction/precode encoding for: " + source);
    }
}

void expect_program_rejected(const std::string& source)
{
    try {
        hpu::validate_executable_program(hpu::assemble_source(source));
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("invalid executable lifetime was accepted");
}

} // namespace

int main()
{
    try {
        if (hpu::dload(0, hpu::DataType::poly).find(
                "dload x10, x11, p0, 1, 0") == std::string::npos
            || hpu::dstore(2, 1).find(
                "dstore x10, x11, p2, 1") == std::string::npos) {
            throw std::runtime_error("runtime DMA register ABI mismatch");
        }
        const std::string smoke =
            "dload x10, x11, p0, 0, 0\n"
            "dload x10, x11, p4, 2, 1\n"
            "pmodld 255\n"
            "padd p2, p0, p1\n"
            "psub p2, p0, p1\n"
            "pmul p2, p0, p1\n"
            "pmac p2, p0, p1\n"
            "pntt p0, p3, 15, 3, 1\n"
            "pintt p0, p3, 15, 3, 1\n"
            "pfree p5\n"
            "dstore x10, x11, p2, 1\n"
            "psync\n";
        const auto encoded = hpu::assemble_source(smoke);
        if (encoded.size() != 12) {
            throw std::runtime_error("unexpected smoke instruction count");
        }
        if ((encoded.front().word & 0x7fU) != 0x2bU
            || (encoded[10].word & 0x7fU) != 0x2bU
            || (encoded[2].word & 0x7fU) != 0x0bU
            || (encoded.back().word & 0x7fU) != 0x0bU) {
            throw std::runtime_error("custom opcode routing mismatch");
        }
        for (const auto& item : encoded) {
            const std::uint32_t expected_kind =
                (item.word & 0x7fU) == 0x2bU ? 1U : 0U;
            if ((item.command26 >> 25U) != expected_kind) {
                throw std::runtime_error("command kind is not encoded in cmd[25]");
            }
            if (expected_kind == 0U && item.command26 != (item.word >> 7U)) {
                throw std::runtime_error("custom0 payload precode mismatch");
            }
        }

        expect_encoded("padd p2, p0, p1", 0x0400400BU);
        expect_encoded("psub p2, p0, p1", 0x1400400BU);
        expect_encoded("pmul p2, p0, p1", 0x2400400BU);
        expect_encoded("pmac p2, p0, p1", 0x3400400BU);
        expect_encoded("pntt p0, p3, 15, 0, 0", 0x40C03C0BU);
        expect_encoded("pintt p0, p3, 15, 0, 0", 0x50C03C0BU);
        expect_encoded("pmodld 0", 0x6000000BU);
        expect_encoded("pmodld 1", 0x6000400BU);
        expect_encoded("pmodld 255", 0x603FC00BU);
        expect_encoded("pfree p4", 0x8100000BU);
        expect_encoded("psync", 0x7000000BU);
        expect_precoded("padd p2, p0, p1", 0x0400400BU, 0x0080080U);
        expect_precoded("pmodld 255", 0x603FC00BU, 0x0C07F80U);
        expect_precoded("dload x10, x11, p0, 0, 0", 0x00B5002BU, 0x2000000U);
        expect_precoded("dload x10, x11, p4, 2, 1", 0x00B5292BU, 0x2000424U);
        expect_precoded("dstore x10, x11, p2, 1", 0x00B5542BU, 0x2000015U);
        expect_encoded("dstore x10, x11, p2, 1", 0x00B5542BU);
        expect_encoded("pmul p2, p0, 255", 0x243FC10BU);
        expect_encoded("pmac p2, p0, 255", 0x343FC10BU);

        const auto executable_encoded = hpu::assemble_source(
            "dload x10, x11, p4, 2, 1\n"
            "pmodld 0\n"
            "dload x10, x11, p0, 1, 0\n"
            "dload x10, x11, p1, 1, 0\n"
            "pmul p2, p0, p1\n"
            "pfree p0\n"
            "pfree p1\n"
            "dstore x10, x11, p2, 1\n"
            "pfree p4\n"
            "psync\n");
        hpu::validate_executable_program(executable_encoded);
        expect_program_rejected(
            "dload x10, x11, p0, 1, 0\n"
            "dload x10, x11, p0, 1, 0\n"
            "psync\n");
        expect_program_rejected(
            "dload x10, x11, p0, 1, 0\n"
            "psync\n"
            "pfree p0\n");
        const std::string executable =
            hpu::render_executable_source("smoke", executable_encoded);
        const std::string header = hpu::render_executable_header(
            "smoke", hpu::collect_dma_relocations(executable_encoded).size());
        const std::string manifest = hpu::render_dma_manifest(executable_encoded);
        if (hpu::collect_dma_relocations(executable_encoded).size() != 4)
            throw std::runtime_error("executable DMA count mismatch");
        if (executable.find("register uintptr_t hpu_rs1 __asm__(\"x10\")")
            == std::string::npos)
            throw std::runtime_error("executable x10 binding mismatch");
        if (executable.find("register uintptr_t hpu_rs2 __asm__(\"x11\")")
            == std::string::npos)
            throw std::runtime_error("executable x11 binding mismatch");
        if (executable.find(".word 0x00B5292B") == std::string::npos)
            throw std::runtime_error("executable fixed word mismatch");
        if (executable.find("spans[3].line_offset") == std::string::npos)
            throw std::runtime_error("executable DSTORE relocation mismatch");
        if (executable.find(
                "hpu_rs2 __asm__(\"x11\") = (uintptr_t)spans[3].line_count;")
            == std::string::npos)
            throw std::runtime_error("executable DSTORE x11/count ABI mismatch");
        if (executable.find("hpu_rs2 __asm__(\"x11\") = 0;")
            != std::string::npos)
            throw std::runtime_error("executable contains zero-length DMA sideband");
        if (header.find("HPU_PROGRAM_SMOKE_DMA_COUNT = 4") == std::string::npos)
            throw std::runtime_error("executable header mismatch");
        if (manifest.find("7,3,dstore,2,1,0,x10,x11,0x00B5542B")
            == std::string::npos)
            throw std::runtime_error("DMA manifest mismatch");

        const std::vector<std::string> invalid{
            "padd p8, p0, p1",
            "padd p0, p1, 1",
            "pmul p0, p1, 256",
            "pntt p0, p1, 16, 0, 0",
            "pntt p0, p1, 0, 4, 0",
            "pntt p0, p1, 0, 0, 2",
            "pmodld 256",
            "pmodld -1",
            "pmodld p0, 0, 0",
            "pfree p8",
            "pfree p0, 0, 0",
            "pshcfg p0, 0, 0",
            "pshuf p0, p1, 0, 0, 0",
            "pseed 0",
            "psample p0, p1, 0, 0, 0",
            "psync 0, 0",
            "dload x32, x0, p0, 0, 0",
            "dload x0, x0, p0, 3, 0",
            "dload x0, x0, p0, 4, 0",
            "dload x0, x0, p0, 0",
            "dload x0, x0, p0, 2, 2",
            "dstore x0, x0, p0, 2",
            "dstore x0, x0, p0, 1, 1",
        };
        for (const std::string& source : invalid) {
            expect_rejected(source);
        }

        std::cout << "HPU encoder self-test: PASS\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "HPU encoder self-test failed: " << exception.what() << '\n';
        return 1;
    }
}
