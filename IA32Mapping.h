
#ifndef IA32MAPPING_H
#define IA32MAPPING_H


#include <cstdint>
#include <map>
#include <fstream>

#include <Zydis/Zydis.h>

#include "Instruction.h"


enum class IA32Operand : uint8_t
{
    /// Explicit register operands
    AL,
    AX,
    EAX,

    /// Relative address operands (implies a mod r/m byte is present)
    r8,
    r16,
    r32,
    r,

    /// Register or memory operands (implies a mod r/m byte is present)
    rm8,
    rm16,
    rm32,
    rm,

    /// Memory operands (implies a mod r/m byte is present)
    m8,
    m16,
    m32,
    m,

    /// Immediate operands
    imm8,
    imm16,
    imm32,
    imm,

    /// Relative address operands
    rel8,
    rel16,
    rel32,
    rel,

    /// Memory offset operands, relative to the segment base
    moffs8,
    moffs16,
    moffs32,
    moffs,

    /// Far pointer operands
    /// Structure: <offset in new segment>:<code segment register value>
    ptr16_16, /// Used for 16 bits operands
    ptr16_32, /// Used for 32 bits operands

    /// Memory operand for a far pointer
    /// Structure: <offset in segment>:<segment>
    m16_16, /// Used for 16 bits operands
    m16_32, /// Used for 32 bits operands

    /// Two memory operands in one (implies NO mod r/m byte is present)
    /// The choice between m16&16 and m32&32 depends on the operand size
    /// m16&32 has a fixed size.
    m16$32,
    m16$16,
    m32$32,

    /// Segment register operand
    Sreg,
};


class IA32Mapping
{
public:
    void load_instruction_mapping(std::fstream& mapping_file);

    bool extract_instruction(const ZydisDecodedInstruction& IA32inst, Instruction& inst) const;

private:

    /**
     * Struct which holds info on how to extract data for one opcode of one instruction of the IA-32 ABI.
     */
    struct IA32Inst {
        char mnemonic[5];                     /// Mnemonic of the instruction

        uint8_t opcode;                       /// Opcode
        uint8_t opcode_ext;                   /// Opcode extension, for instructions with 2 bytes opcodes

        uint8_t equiv_opcode;                 /// Equivalent opcode in our instruction set

        // Size override flags

        bool keep_overrides : 1;              /// Keep the size overrides and ignore the values below
        bool address_size_override : 1;       /// Force 16-bit addresses
        bool operand_size_override : 1;       /// Force 16-bit operands
        bool address_byte_size_override : 1;  /// Force 8-bit addresses
        bool operand_byte_size_override : 1;  /// Force 8-bit operands

        // Operands. All instructions we consider have at most 2 operands (excluding immediates)

        OpType operand_1_type : 3;            /// Type of the first operand
        OpType operand_2_type : 3;            /// Type of the second operand

        uint8_t operand_1_register : 3;       /// If the first operand is of register type, the register index associated
        uint8_t operand_2_register : 3;       /// If the second operand is of register type, the register index associated

        bool read_operand_1 : 1;              /// Do we read the value of the first operand
        bool read_operand_2 : 1;              /// Do we read the value of the second operand

        // Return value

        bool write_ret_1_to_op_1 : 1;         /// Write the first return value to the first operand
        bool write_ret_2_to_op_2 : 1;         /// Write the second return value to the second operand

        bool write_ret_1_register : 1;        /// Write the first return value to a specific register
        bool write_ret_1_register_scale : 1;  /// Use the size overrides for the size of the return value
        uint8_t write_ret_1_out_register : 3; /// Output register index of the return value

        // More specific flags

        bool compute_address : 1;             /// Compute the address in the Mod r/m (+ SIB) byte
        bool has_mod_SIB : 1;                 /// Extract the Mod r/m (+SIB) byte(s)
        bool reg_and_rm_operands : 1;         /// /r in the opcode in the manual. The Mod r/m has both a register and a r/m operand

        // Immediates

        bool extract_immediate_address : 1;   /// Extract the constant address
        bool constant_immediate_value : 1;    /// There is a constant immediate value (ignore the one of the instruction)
        uint8_t : 0; // (align here)
        uint32_t immediate_value;             /// Constant immediate value
    };

    std::map<uint16_t, const IA32Inst> IA32_instructions;
};


#endif //IA32MAPPING_H
