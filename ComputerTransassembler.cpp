
#include <cstdio>
#include <Zydis/Zydis.h>
#include <elfio.hpp>

#include "Transassembler.h"


static ZydisFormatter formatter;

static IA32::Mapping mapping;

static ComputerOpcodesInfo opcodes_info;


bool load_opcodes_mapping(const std::string& opcodes_mapping_file)
{
    std::fstream opcodes_file;
    opcodes_file.open(opcodes_mapping_file, std::ios::in);
    if (!opcodes_file.is_open()) {
        std::cerr << "Cannot open the opcodes file: " << opcodes_mapping_file << std::endl;
        return true;
    }
    else {
        try {
            if (opcodes_info.load_map(opcodes_file)) {
                std::cerr << "Parsing error for the opcodes file: " << opcodes_mapping_file << std::endl;
                return true;
            }
        } catch (const std::exception& e) {
            std::cerr << "Parsing error for the opcodes file: " << opcodes_mapping_file << "\n" << e.what() << std::endl;
            return true;
        }
    }
    opcodes_file.close();

    return false;
}


bool load_mapping(const std::string& mapping_file_name)
{
    std::fstream mapping_file;
    mapping_file.open(mapping_file_name, std::ios::in);
    if (!mapping_file.is_open()) {
        std::cerr << "Cannot open the mapping file: " << mapping_file_name << std::endl;
        return true;
    }

    try {
        if (mapping.load_instructions_extract_info(mapping_file, opcodes_info)) {
            std::cerr << "Parsing error for the mapping file: " << mapping_file_name << std::endl;
            return true;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error while loading the mapping file: \n" << e.what() << "\n";
        return false;
    }

    mapping_file.close();

    return false;
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

    // The first segment is guaranteed to be the one containing all the interesting code by the linker script
    const ELFIO::segment* segment = elf_reader.segments[0];
    printf("Disassembling segment %d...\n", segment->get_index());

    Transassembler transassembler((const uint8_t*) segment->get_data(), segment->get_file_size(), segment->get_virtual_address());
    transassembler.process_code_segment_references();
    transassembler.print_disassembly(formatter);
    transassembler.convert_instructions(mapping);

    printf("Successfully disassembled segment %d.\n", segment->get_index());

    return 0;
}


int main()
{
    const std::string elf_file = "./ProgramCore/Program_core.exe";
    const std::string mapping_file_name = "./IA32_instructions_mapping.csv";
    const std::string opcodes_mapping_file_name = "./computer_instructions.csv";

    if (!load_opcodes_mapping(opcodes_mapping_file_name)) {
        return 1;
    }

    if (!load_mapping(mapping_file_name)) {
        return 1;
    }

    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    if (!disassemble_elf(elf_file)) {
        return 1;
    }

    return 0;
}
