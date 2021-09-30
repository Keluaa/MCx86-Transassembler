
#include <iostream>
#include <filesystem>

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


void write_memory_map(const std::string& file_name, ELFIO::Elf32_Addr entry_point, uint32_t instructions_count)
{
    // See the custom linker script (linking.ld) for the custom memory layout
    const ELFIO::Elf32_Addr text_start = 0x010000;
    const ELFIO::Elf32_Addr rom_start = 0x200000;
    const ELFIO::Elf32_Addr ram_start = 0x400000;

    std::ofstream memory_map_file(file_name);
    if (!memory_map_file) {
        std::cout << "Could not open the memory map file: '" << file_name << "'" << std::endl;
        return;
    }

    memory_map_file << std::hex;
    memory_map_file << entry_point << "\n";
    memory_map_file << text_start << "\n";
    memory_map_file << text_start + instructions_count << "\n";
    memory_map_file << rom_start;
    memory_map_file << ram_start;

    memory_map_file.close();
}


void write_memory_contents(const std::string& file_name, const ELFIO::segment* data_segment)
{
    // TODO : check that the changes applied to the labels section are still present in the data segment

    const std::streamsize CHUNK_SIZE = 4096; // Write to the file by chunks of 4 kB

    std::filebuf memory_file;
    if (!memory_file.open(file_name, std::ios::out | std::ios::binary)) {
        std::cout << "Could not open the memory data file: '" << file_name << "'" << std::endl;
        return;
    }

    const char* data = data_segment->get_data();
    std::streamsize pos = 0;
    std::streamsize size = std::streamsize(data_segment->get_file_size());

    while (pos < size) {
        memory_file.sputn(data, std::min(CHUNK_SIZE, size - pos));
        memory_file.pubsync(); // flush the file buffer

        data += CHUNK_SIZE;
        pos += CHUNK_SIZE;
    }

    memory_file.close();
}


int transassemble_elf(const std::string& elf_file)
{
    const std::string instructions_file_name = "instructions.bin";

    ELFIO::elfio elf_reader;

    if (!elf_reader.load(elf_file)) {
        std::cerr << "Could not open the elf file: " << elf_file << std::endl;
        return 1;
    }

    std::cout << "Transassembling '" << elf_file << "'...\n";

    // Get the section containing labels (addresses) to instructions
    // This section may be absent.
    const ELFIO::section* labels_section = elf_reader.sections[".labels"];
    
    // The first segment is guaranteed to be the one containing all the interesting code by the linker script
    const ELFIO::segment* segment = elf_reader.segments[0];

    Transassembler transassembler((const uint8_t*) segment->get_data(), segment->get_file_size(), segment->get_virtual_address());

    std::cout << "Processing jumps..." << std::endl;
    transassembler.process_jumping_instructions();

    if (labels_section != nullptr) {
        // I am too lazy to create a new data array and set it, so const_cast it is
        std::cout << "Re-writing the labels section... (for " << (labels_section->get_size() / 4) << " labels)" << std::endl;
        transassembler.update_labels_section(elf_reader.get_convertor(),
                                             reinterpret_cast<uint8_t*>(const_cast<char*>(labels_section->get_data())),
                                             labels_section->get_size());
    }
    else {
        std::cout << "No labels section." << std::endl;
    }

    std::filebuf instructions_file;
    if (!instructions_file.open(instructions_file_name, std::ios::out | std::ios::binary)) {
        std::cout << "Could not open the instructions file: '" << instructions_file_name << "'" << std::endl;
        return 1;
    }

    std::cout << "Converting instructions..." << std::endl;
    transassembler.convert_instructions(mapping, instructions_file);

    instructions_file.close();
	
    std::cout << "Successfully transassembled the elf file." << std::endl;

    write_memory_map("memory_map.txt", elf_reader.get_entry(), transassembler.get_instructions_count());

    write_memory_contents("memory_data.bin", elf_reader.segments[2]);

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

    if (!transassemble_elf(elf_file)) {
        return 1;
    }

    return 0;
}
