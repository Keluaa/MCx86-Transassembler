#ifndef TRANSASSEMBLER_H
#define TRANSASSEMBLER_H

#include <map>
#include <unordered_map>
#include <cstdint>
#include <exception>
#include <sstream>

#include "Zydis/Zydis.h"
#include "elfio/elfio.hpp"

#include "Instruction.h"
#include "IA32Mapping.h"


class Transassembler {

public:

    static bool is_instruction_a_jump(const ZydisDecodedInstruction& inst);
    static bool does_instruction_branches(const ZydisDecodedInstruction& inst);

    static ZyanUSize get_jump_address(const ZydisDecodedInstruction& inst, const ZyanUSize inst_address);

    static Register scale_register(uint8_t index, bool operand_size_override, bool operand_byte_size_override,
                                   const uint32_t virtual_address);

    static Register operand_to_register(IA32::Operand register_operand,
                                        bool operand_size_override, bool operand_byte_size_override,
                                        const uint32_t virtual_address);

    static uint32_t operand_to_immediate(IA32::Operand immediate_operand, const ZydisDecodedOperand& operand,
                                         const uint32_t virtual_address);

    static void convert_operand(const ZydisDecodedInstruction& IA32inst, const IA32::Inst& extract_data, Instruction& inst,
                                uint32_t virtual_address, uint32_t segment_base_address,
                                uint8_t op_index, const IA32::Operand& inst_operand, Instruction::Operand& op,
                                bool rm_is_register_operand, uint8_t rm_index, uint8_t sib_scale);

    static void post_conversion(const ZydisDecodedInstruction& IA32inst, Instruction& inst);

    static void extract_mod_rm_sib_bytes(const ZydisDecodedInstruction& IA32inst, Instruction& inst,
                                         bool& rm_is_register_operand, uint8_t& register_index, uint8_t& sib_scale);

    Transassembler(const IA32::Mapping* mapping, const uint8_t* data, const size_t size, const uint64_t addr);

    void process_jumping_instructions();

    void convert_instruction(const ZydisDecodedInstruction& IA32inst, Instruction& inst,
                             uint32_t virtual_address, uint32_t segment_base_address) const;

    /**
     * Parses through all instructions, decodes them, converts them, and writes the new instruction to the file as raw
     * binary.
     *
     * Jumping instructions have their target corrected using the jump target map built from process_jumping_instructions().
     */
    void convert_instructions(std::filebuf& out_file);

    /**
     * Converts the contents of the labels section, where all pointer lookup tables to other instructions are stored,
     * using the map for all instruction positions.
     */
    void update_labels_section(const ELFIO::endianess_convertor& conv, uint8_t* data, size_t labels_size);

    /**
     * Prints instructions with their address, number and jump numbers.
     */
    void print_disassembly(const ZydisFormatter& formatter) const;

    uint32_t get_instructions_count() const { return instructions_numbers.size(); }

private:

    /**
     * Mapping from IA32 instructions to features of our instructions
     */
    const IA32::Mapping* mapping;

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


class TransassemblingException : public std::exception
{
protected:
    std::string msg;

public:
    TransassemblingException(const char* msg, const ZydisDecodedInstruction& inst) noexcept
    {
        uint16_t opcode = inst.opcode;
        opcode |= inst.opcode_map == ZYDIS_OPCODE_MAP_0F ? 0x0F00 : 0x0000;

        std::stringstream ss;
        ss << msg;
        ss << "\nFaulty instruction: " << ZydisMnemonicGetString(inst.mnemonic) << " (0x" << std::hex << opcode << ")";
        this->msg = ss.str();
    }

    TransassemblingException(const char* msg, const ZydisDecodedInstruction& inst, ZyanUSize address) noexcept
    {
        uint16_t opcode = inst.opcode;
        opcode |= inst.opcode_map == ZYDIS_OPCODE_MAP_0F ? 0x0F00 : 0x0000;

        std::stringstream ss;
        ss << msg;
        ss << "\nFaulty instruction: " << ZydisMnemonicGetString(inst.mnemonic) << " (0x" << std::hex << opcode << ")";
        ss << "\nAddress: 0x" << address << "\n";
        this->msg = ss.str();
    }

    [[nodiscard]] const char* what() const noexcept override { return msg.c_str(); }
};


class ConversionException : public std::exception
{
public:
    template<typename... Args>
    ConversionException(uint32_t inst_address, const std::string& msg, Args... args)
    {
        std::string format = "At 0x%x: ";
        format.append(msg);

        int length = snprintf(nullptr, 0, format.c_str(), inst_address, args...);
        if (length < 0) {
            message = msg;
            return;
        }

        char* buffer = new char[length + 1];
        snprintf(buffer, length + 1, format.c_str(), inst_address, args...);

        message = buffer;
        delete[] buffer;
    }

    [[nodiscard]] const char* what() const noexcept override
    {
        return message.c_str();
    }

private:
    std::string message;
};


#endif //TRANSASSEMBLER_H
