
#ifndef IA32MAPPING_H
#define IA32MAPPING_H


#include <cstdint>
#include <unordered_set>
#include <unordered_map>
#include <fstream>

#include <Zydis/Zydis.h>

#include "Instruction.h"
#include "ComputerOpcodesInfo.h"


namespace IA32
{
    enum class Operand : uint8_t;

    struct Inst;

    class Mapping;

    class ConversionException;
    class LoadingException;
}


enum class IA32::Operand : uint8_t
{
    None,

    /// Explicit register operands
    AL,
    AH,
    EAX,

    CL,
    ECX,

    DL,
    EDX,

    /// Scaled register operands, they only specify an index, the size will be determined by the operand size
    A,   /// AL, AX, EAX
    C,   /// CL, CX, ECX
    D,   /// DL, DX, EDX
    B,   /// BL, BX, EBX

    /// Explicit segment registers operands
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,

    /// Register operands, encoded into the opcode of the instruction (+r[b,w,d] in the manual)
    reg, /// 32 or 16 bits depending on the operand size
    reg8,

    /// Register operands (implies a mod r/m byte is present)
    r,   /// 32 or 16 bits depending on the operand size
    r8,
    r16,
    r32,

    /// Register or memory operands (implies a mod r/m byte is present)
    rm,  /// 32 or 16 bits depending on the operand size
    rm8,
    rm16,

    /// Memory operands (implies a mod r/m byte is present)
    m,   /// 32 or 16 bits depending on the operand size
    m8,

    /// Immediate operands
    imm,
    imm8,
    imm16,
    imm32,

    /// Constant immediate operand
    cst,

    /// Relative address operands
    rel,      /// 8, 16 or 32 bits depending on the operand size

    /// Memory offset operands, relative to the segment base
    moffs,    /// 8, 16 or 32 bits depending on the operand size

    /// Far pointer operands
    /// Structure: <offset in new segment>:<code segment register value>
    ptr16_32, /// Used for 32 bits operands, ptr16_16 is used for 16 bits operands

    /// Memory operand for a far pointer
    /// Structure: <offset in segment>:<segment>
    m16_32,  /// Used for 32 bits operands, m16_16 is used for 16 bits operands

    /// Two memory operands in one (implies NO mod r/m byte is present)
    /// m16&32 has doesn't change its size with the operand size override.
    m16$32,
    m32$32,  /// Used for 32 bits operands, m16$16 is used for 16 bits operands

    /// Segment register operand
    Sreg,

    /// Control register operand
    Creg,
};


/**
 * Struct which holds info on how to extract data for one opcode of one instruction of the IA-32 ABI.
 */
struct IA32::Inst
{
    char mnemonic[6];                     /// Mnemonic of the instruction

    uint16_t opcode;                      /// Opcode

    char equiv_mnemonic[6];               /// Equivalent mnemonic in out instruction set
    uint8_t equiv_opcode;                 /// Equivalent opcode in our instruction set

    // Size override flags

    bool keep_overrides : 1;              /// Keep the size overrides and ignore the two values below

    // Operands. All instructions we consider have at most 2 operands (and one optional third immediate operand)

    Operand operand_1 : 6;                /// Type of the first operand
    Operand operand_2 : 6;                /// Type of the second operand

    Operand operand_3_imm : 6;            /// For 3 operands instructions with an immediate as the third operand
    bool has_immediate_operand : 1;       /// For 3 operands instructions with an immediate as the third operand

    bool read_operand_1 : 1;              /// Do we read the value of the first operand
    bool read_operand_2 : 1;              /// Do we read the value of the second operand

    // Return value(s)

    bool write_ret_1_to_op_1 : 1;         /// Write the first return value to the first operand
    bool write_ret_2_to_op_2 : 1;         /// Write the second return value to the second operand

    bool write_ret_2_register : 1;        /// Write the second return value to the specific register
    bool write_ret_register_scale : 1;    /// Use the size overrides for the size of the specific register
    Operand write_ret_out_register : 6;   /// Specific register index in the general purpose registers

    // Other flags

    bool has_mod_byte : 1;                /// Extract the Mod r/m byte (and the SIB byte if present)
    bool get_flags : 1;                   /// The instruction needs the CPU flags (to either read and/or write)
    bool get_CR0 : 1;                     /// The instruction needs the CR0 flags (only read)

    uint8_t : 0; // alignment

    uint8_t immediate_value;             /// Constant immediate value for the instruction
};


class IA32::Mapping
{
public:
    bool load_instructions_extract_info(std::fstream& mapping_file, const ComputerOpcodesInfo& opcodes_info);

    static constexpr Register scale_register(uint8_t index,
                                             bool operand_size_override, bool operand_byte_size_override,
                                             const uint32_t& virtual_address);

    static void convert_operand(const ZydisDecodedInstruction& IA32inst, const IA32::Inst& extract_data, Instruction& inst,
                                uint32_t virtual_address, uint32_t segment_base_address, uint8_t op_index,
                                const Operand& inst_operand, Instruction::Operand& op,
                                bool rm_is_register_operand, uint8_t rm_index);

    static void post_conversion(const ZydisDecodedInstruction& IA32inst, Instruction& inst);

    void convert_instruction(const ZydisDecodedInstruction& IA32inst, Instruction& inst,
                             uint32_t virtual_address, uint32_t segment_base_address) const;

private:
    std::unordered_set<uint16_t> opcodes_with_reg_extension;
    std::unordered_map<uint16_t, const IA32::Inst> instructions_extraction_info;
};


class IA32::LoadingException : public std::exception
{
public:
	template<typename... Args>
    LoadingException(const char* format, Args... args)
    {
        int length = snprintf(nullptr, 0, format, args...);
        if (length < 0) {
            message = format;
            return;
        }

        char* buffer = new char[length + 1];
        snprintf(buffer, length + 1, format, args...);

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


class IA32::ConversionException : public std::exception
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


#endif //IA32MAPPING_H
