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


class Transassembler
{
    bool is_instruction_a_jump() const;
    bool does_instruction_branches() const;
    ZyanUSize get_jump_address(ZyanUSize inst_address) const;

    Register scale_register(uint8_t index) const;
    Register scale_register(uint8_t index, bool size_override, bool byte_size_override) const;
    Register operand_to_register(IA32::Operand register_operand) const;
    uint32_t operand_to_immediate(IA32::Operand immediate_operand, const ZydisDecodedOperand& operand) const;

    void extract_mod_rm_sib_bytes();
    void convert_operand(const IA32::Inst& extract_data, uint8_t op_index);
    void post_conversion();

public:
    Transassembler(const IA32::Mapping* mapping, const uint8_t* data, const size_t size, const uint64_t addr);

    void process_jumping_instructions();
    void update_labels_section(const ELFIO::endianess_convertor& conv, uint8_t* data, size_t labels_size);

    void decode_instruction(ZyanUSize runtime_address, const uint8_t* encoded_data, size_t data_size);
    void convert_instruction(Instruction& inst, uint32_t inst_virtual_address, uint32_t segment_base_address);

    void convert_instructions(std::filebuf& out_file);
    void write_instruction_map(std::ofstream& out_file);

    void print_disassembly();

    uint32_t get_instructions_count() const { return instructions_numbers.size(); }

private:
    /**
     * Number of operands to decode.
     *
     * We only need 3: the first two are the main operands of most instructions, the third is the occasional additional
     * immediate operand.
     */
    static const uint8_t USEFUL_OPERANDS_COUNT = 3;

    // Results of 'decode_instruction'
    ZydisDecodedInstruction IA32_inst{};
    ZydisDecodedOperand IA32_operands[USEFUL_OPERANDS_COUNT]{};

    // Fields used by 'convert_instruction' while converting an instruction
    Instruction* MCID32_inst = nullptr;
    uint32_t segment_base_address = 0;
    ZyanUSize virtual_address = 0;
    bool operand_size_override = false;
    bool operand_byte_size_override = false;
    bool rm_is_register_operand = false;
    uint8_t register_index = 0;
    uint8_t sib_scale = 0;

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
    std::map<ZyanUSize, uint32_t> instructions_numbers;
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
