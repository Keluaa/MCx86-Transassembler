
#include <cstdio>
#include <Zydis/Zydis.h>
#include <elfio.hpp>

#include "Transassembler.h"


static ZydisFormatter formatter;

static IA32Mapping mapping;

// voir https://refspecs.linuxfoundation.org/elf/elf.pdf


// Linker Scripts:
// https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_chapter/ld_3.html
// https://wiki.osdev.org/Linker_Scripts

// objcopy pour créer des raw binary file depuis des elf: https://stackoverflow.com/a/3615574/8662187


int load_mapping(const std::string& mapping_file_name)
{
    std::fstream mapping_file;
    mapping_file.open(mapping_file_name, std::ios::in);
    if (mapping_file.bad()) {
        std::cerr << "Could not open the mapping file: " << mapping_file_name << std::endl;
        return 1;
    }

    mapping.load_instruction_mapping(mapping_file);

    return 0;
}


int disassemble_elf(const std::string& elf_file)
{
    ELFIO::elfio elf_reader;

    if (!elf_reader.load(elf_file)) {
        std::cerr << "Could not open the elf file: " << elf_file << std::endl;
        return 1;
    }

    puts("Segments:");
    puts("  i -|- t -|-  s  -|- R W X -|");
    for (const ELFIO::segment* segment : elf_reader.segments) {
        if (segment->get_type() > 10) {
            continue; // compiler info segment
        }

        printf(" %3d |  %d  |  %3d  |  %d %d %d\n",
               segment->get_index(), segment->get_type(), segment->get_sections_num(),
               bool(segment->get_flags() & PF_R),
               bool(segment->get_flags() & PF_W),
               bool(segment->get_flags() & PF_X));
    }

    const ELFIO::Elf32_Addr entry_point = elf_reader.get_entry();

    printf("Entry point: 0x%x\n", entry_point);

    // The first segment is guaranteed to be the one containing all of the interesting code by the linker script
    const ELFIO::segment* segment = elf_reader.segments[0];
    printf("Disassembling segment %d...\n", segment->get_index());

    Transassembler transassembler((const uint8_t*) segment->get_data(), segment->get_file_size(), segment->get_virtual_address());
    transassembler.process_jumps();
    transassembler.print_disassembly(formatter);
    transassembler.convert_instructions(mapping);

    printf("Successfully disassembled segment %d.\n", segment->get_index());

    return 0;
}


int main()
{
    const std::string elf_file = "./ProgramCore/Program_core.exe";
    const std::string mapping_file_name = "./IA32_instructions_mapping.csv";

    if (!load_mapping(mapping_file_name)) {
        return 1;
    }

    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    if (!disassemble_elf(elf_file)) {
        return 1;
    }

    return 0;
}
