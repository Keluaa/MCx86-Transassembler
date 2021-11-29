﻿#ifndef TRANSASSEMBLER_H
#define TRANSASSEMBLER_H

#include <map>
#include <unordered_map>
#include <cstdint>

#include <Zydis/Zydis.h>
#include <elfio.hpp>
#include <elfio_utils.hpp>

#include "Instruction.h"
#include "IA32Mapping.h"


class Transassembler {

public:

    static constexpr bool is_instruction_a_jump(const ZydisDecodedInstruction& inst);
    static constexpr bool does_instruction_branches(const ZydisDecodedInstruction& inst);

    /**
     * Returns the absolute address the instruction jumps to.
     * If the jump is determined at run time (the address is in a register) an assertion fails.
     * If the instruction doesn't jump, or if the jump address is stored in the stack, then it returns 0.
     *
     * @param inst The jumping instruction
     * @param addr The absolute address of the instruction (not counting its length)
     * @return The absolute address of the jump, or 0
     */
    static constexpr ZyanUSize get_jump_address(const ZydisDecodedInstruction& inst, const ZyanUSize inst_address);

    Transassembler(const uint8_t* data, const size_t size, const uint64_t addr);

    /**
     * Parses through all instructions to create a map of all instructions with jumps and to which instruction they jump
     * to. Also builds the map from instruction address to instruction index (instructions_numbers).
     *
     * This operation allows to freely edit instructions without worrying about size changes. Since most jumps are
     * relative offsets from the current instruction, we cannot change the size of an instruction without changing the
     * jumps offsets. This is equivalent to going back to using assembly labels.
     * However doing this implies that we know all offsets we jump to at compile time, meaning that any jumps using
     * register values cannot be processed here.
     */
    void process_jumping_instructions();

    /**
     * Parses through all instructions, decodes them, converts them, and writes the new instruction to the file as raw
     * binary.
     *
     * Jumping instructions have their target corrected using the jump target map built from process_jumping_instructions().
     */
    void convert_instructions(const IA32::Mapping& mapping, std::filebuf& out_file);

    /**
     * Converts the contents of the labels section, where all pointer lookup tables to other instructions are stored,
     * using the map for all instruction positions.
     */
    void update_labels_section(const ELFIO::endianess_convertor& conv, uint8_t* data, size_t labels_size);

    /**<
     * Prints instructions with their address, number and jump numbers.
     */
    void print_disassembly(const ZydisFormatter& formatter) const;

    uint32_t get_instructions_count() const { return instructions_numbers.size(); }

private:

    /**
     * Raw encoded x86 instructions
     */
    const uint8_t* data;

    /**
     * Size of the data array, in bytes
     */
    const size_t size;

    /**
     * Virtual runtime address of the segment being decoded
     */
    const uint64_t segment_address;

    /**
     * x86 instructions decoder
     */
    ZydisDecoder decoder;
        
    /**
     * Map of instructions with a jump, and the instruction number they jump to.
     */
    std::unordered_map<uint32_t, uint32_t> processed_jumping_instructions;

    /**
     * Maps the address of all instructions to their index.
     */
    std::map<ZyanUSize, uint32_t> instructions_numbers; // TODO : maybe remove this by adding the labels as unprocessed jump targets in convert_instructions()
};


#endif //TRANSASSEMBLER_H
