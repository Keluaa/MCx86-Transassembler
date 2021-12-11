
#include <iostream>

#include <Zydis/Zydis.h>
#include <elfio/elfio.hpp>

#include "transassembler/Transassembler.h"


static ZydisFormatter formatter;
static IA32::Mapping mapping;
static ComputerOpcodesInfo opcodes_info;


bool load_opcodes_mapping(const std::string& opcodes_mapping_file)
{
    std::fstream opcodes_file;
    opcodes_file.open(opcodes_mapping_file, std::ios::in);
    if (!opcodes_file) {
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

    std::cout << "Loaded the opcodes map\n";

    return false;
}


bool load_mapping(const std::string& mapping_file_name)
{
    std::fstream mapping_file;
    mapping_file.open(mapping_file_name, std::ios::in);
    if (!mapping_file) {
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
        return true;
    }

    mapping_file.close();

    std::cout << "Loaded the instructions extraction infos\n";

    return false;
}


void write_memory_map(const std::string& file_name, ELFIO::Elf32_Addr entry_point, uint32_t instructions_count, uint32_t raw_rom_size, uint32_t raw_ram_size)
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
    memory_map_file << rom_start << "\n";
    memory_map_file << ram_start << "\n";
    memory_map_file << raw_rom_size << "\n";
    memory_map_file << raw_ram_size << "\n";

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
    std::streamsize pos = 0, size = std::streamsize(data_segment->get_file_size());

    while (pos < size) {
        memory_file.sputn(data, std::min(CHUNK_SIZE, size - pos));
        memory_file.pubsync(); // flush the file buffer

        data += CHUNK_SIZE;
        pos += CHUNK_SIZE;
    }

    memory_file.close();
}


std::pair<uint32_t, uint32_t> get_data_sizes(ELFIO::elfio& elf_reader)
{
    ELFIO::section* symbol_table_section = elf_reader.sections[".symtab"];
    ELFIO::symbol_section_accessor symbol_table(elf_reader, symbol_table_section);

    auto get_symbol_value = [symbol_table](const std::string& name) {
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword size;
        unsigned char bind;
        unsigned char type;
        ELFIO::Elf_Half section_index;
        unsigned char other;

        symbol_table.get_symbol(name, value, size, bind, type, section_index, other);

        return value;
    };

    ELFIO::Elf64_Addr rodata_start = get_symbol_value("rodata_start");
    ELFIO::Elf64_Addr rodata_end = get_symbol_value("rodata_end");
    ELFIO::Elf64_Addr data_start = get_symbol_value("data_start");
    ELFIO::Elf64_Addr data_end = get_symbol_value("data_end");

    uint32_t rodata_raw_size = rodata_end - rodata_start;
    uint32_t data_raw_size = data_end - data_start;

    return std::make_pair(rodata_raw_size, data_raw_size);
}


bool transassemble_elf(const std::string& elf_file, const std::string& out_folder)
{
    const std::string instructions_file_name = out_folder + "/instructions.bin";
    const std::string memory_map_file_name = out_folder + "/memory_map.txt";
    const std::string memory_data_file_name = out_folder + "/memory_data.bin";

    ELFIO::elfio elf_reader;

    if (!elf_reader.load(elf_file)) {
        std::cerr << "Could not open the elf file: " << elf_file << std::endl;
        return true;
    }

    auto [raw_rom_size, raw_ram_size] = get_data_sizes(elf_reader);

    std::cout << "Raw ROM size: " << raw_rom_size << " bytes.\n";
    std::cout << "Raw RAM size: " << raw_ram_size << " bytes.\n";

    std::cout << "Transassembling '" << elf_file << "'...\n";

    // Get the section containing labels (addresses) to instructions
    // This section may be absent.
    const ELFIO::section* labels_section = elf_reader.sections[".labels"];
    
    // The first segment is guaranteed to be the one containing all the interesting code by the linker script
    const ELFIO::segment* segment = elf_reader.segments[0];

    Transassembler transassembler(&mapping, (const uint8_t*) segment->get_data(), segment->get_file_size(), segment->get_virtual_address());

    std::cout << "Processing jumps..." << std::endl;
    try {
        transassembler.process_jumping_instructions();
    }
    catch (const TransassemblingException& exception) {
        std::cout << "Could not process jumps.\n" << exception.what();
        return true;
    }

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
        return true;
    }

    std::cout << "Converting instructions..." << std::endl;

    try {
    	transassembler.convert_instructions(instructions_file);
	}
	catch (const ConversionException& e) {
		std::cout << "Conversion error: \n" << e.what() << "\n";
		return true;
	}

    instructions_file.close();
	
    std::cout << "Successfully transassembled the elf file." << std::endl;

    write_memory_map(memory_map_file_name, elf_reader.get_entry(), transassembler.get_instructions_count(), raw_rom_size, raw_ram_size);
    write_memory_contents(memory_data_file_name, elf_reader.segments[2]);

    return false;
}


int main()
{
    const std::string elf_file = "./ProgramCore/Program_core.exe";
    const std::string mapping_file_name = "./mappings/IA32_instructions_mapping.csv";
    const std::string opcodes_mapping_file_name = "./mappings/computer_instructions.csv";
    const std::string out_folder = "./out";

    if (load_opcodes_mapping(opcodes_mapping_file_name)) {
        return 1;
    }

    if (load_mapping(mapping_file_name)) {
        return 1;
    }

    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    if (transassemble_elf(elf_file, out_folder)) {
        return 1;
    }

    return 0;
}
