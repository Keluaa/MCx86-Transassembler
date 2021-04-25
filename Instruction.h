
#ifndef COMPUTERTRANSASSEMBLER_INSTRUCTION_H
#define COMPUTERTRANSASSEMBLER_INSTRUCTION_H

#include <cstdint>


enum class OpType : uint8_t {
    REG,
    MEM,
    IMM,
    IMM_MEM,
};


enum class Register : uint8_t {
    EAX = 0,
    ECX = 1,
    EDX = 2,
    EBX = 3,
    ESP = 4,
    EBP = 5,
    ESI = 6,
    EDI = 7,

    AX = 0b01000 | 0,
    CX = 0b01000 | 1,
    DX = 0b01000 | 2,
    BX = 0b01000 | 3,
    SP = 0b01000 | 4,
    BP = 0b01000 | 5,
    SI = 0b01000 | 6,
    DI = 0b01000 | 7,

    AL = 0b10000 | 0,
    CL = 0b10000 | 1,
    DL = 0b10000 | 2,
    BL = 0b10000 | 3,
    AH = 0b10000 | 4,
    CH = 0b10000 | 5,
    DH = 0b10000 | 6,
    BH = 0b10000 | 7,

    CS = 0b11000 | 0,
    SS = 0b11000 | 1,
    DS = 0b11000 | 2,
    ES = 0b11000 | 3,
    FS = 0b11000 | 4,
    GS = 0b11000 | 5,

    CR0 = 0b11000 | 6,
    CR1 = 0b11000 | 7,
};


/**
 * Instruction for our computer.
 *
 * It is not encoded, which simplifies the circuitry by a lot, however this comes at the cost of bigger
 * memory usage, but by design this is not a problem. The only downside is that the executable files are
 * bigger.
 *
 * Total size: 112 bits used, but 128 bits in memory
 */
struct Instruction {

    uint8_t opcode;

    /// Struct describing an operand, present in order for IA32::Mapping::convert_operand to exist.
    /// An additional field for 'write' would have been great but the struct is already 8 bits long.
    struct Operand {
        OpType type : 2;
        Register reg : 5;
        bool read : 1;

        constexpr bool operator==(const Operand& other) const = default;
    } op1, op2;

    // Flags
    bool operand_size_override : 1;
    bool operand_byte_size_override : 1;

    // No address size override, since we impose 32-bit addressing for simplicity

    bool get_flags : 1;
    bool get_CR0 : 1;

    // Output
    bool write_ret1_to_op1 : 1;
    bool write_ret2_to_op2 : 1;

    bool write_ret2_to_register : 1;
    bool scale_output_override : 1;
    Register register_out : 5;

    // Addressing
    // An effective address needs to be computed if any of reg_present, base_present or displacement_present is true
    bool reg_present : 1;
    uint8_t reg : 3;
    uint8_t scale : 2;
    bool base_present : 1;
    uint8_t base_reg : 3;
    uint8_t displacement_present : 1; // The displacement is stored in the address_value field

    uint8_t : 0; // alignment (16 bits)

    // both of those values can be used as general purpose values in special instructions (bound, call...)
    uint32_t address_value;
    uint32_t immediate_value;

    // The Operand struct by itself cannot describe when it is not use, here is how to do it for both operands:
    [[nodiscard]] constexpr bool is_op1_none() const { return !op1.read && !write_ret1_to_op1; }
    [[nodiscard]] constexpr bool is_op2_none() const { return !op2.read && !write_ret2_to_op2; }

    constexpr bool operator==(const Instruction& other) const = default;
};


#endif //COMPUTERTRANSASSEMBLER_INSTRUCTION_H
