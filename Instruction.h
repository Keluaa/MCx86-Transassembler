
#ifndef COMPUTERTRANSASSEMBLER_INSTRUCTION_H
#define COMPUTERTRANSASSEMBLER_INSTRUCTION_H

#include <cstdint>


enum class OpType : uint8_t {
    NONE,
    REG,
    MEM,
    IMM,
    ABS_MEM,
    SREG,
    CREG
};


enum class Register : uint8_t {
    EAX = 0, // AL, AX, EAX
    ECX = 1, // CL, CX, ECX
    EDX = 2, // DL, DX, EDX
    EBX = 3, // BL, BX, EBX
    ESP = 4, // AH, SP, ESP
    EBP = 5, // CH, BP, EBP
    ESI = 6, // DH, SI, ESI
    EDI = 7, // BH, DI, EDI
};


/**
 * Instruction for our computer.
 *
 * It is not encoded, which simplifies the circuitry by a lot, however this comes at the cost of bigger
 * memory usage, but by design this is not a problem. The only downside is that the executable files are
 * bigger.
 */
struct Instruction {

    uint8_t opcode;

    // Flags
    bool address_size_override : 1;
    bool operand_size_override : 1;
    bool address_byte_size_override : 1;
    bool operand_byte_size_override : 1;

    bool get_flags : 1;
    // TODO : add special flags, like get/set Control Registers

    // Operands
    OpType op1_type : 3;
    OpType op2_type : 3;

    Register op1_register : 3;
    Register op2_register : 3;

    // Input
    bool read_op1 : 1;
    bool read_op2 : 1;

    // Output
    bool write_ret1_to_op1 : 1;
    bool write_ret2_to_op2 : 1;

    bool write_ret1_to_register : 1;
    bool scale_output_override : 1;
    uint8_t register_out : 3;

    // Addressing
    // An effective address needs to be computed if any of reg_present, base_present or displacement_present is true
    bool reg_present : 1;
    uint8_t reg : 3;
    uint8_t scale : 2;
    bool base_present : 1;
    uint8_t base_reg : 3;
    uint8_t displacement_present : 1; // The displacement is stored in the address_value field

    uint8_t : 0; // alignment (2 bits of padding)

    // both of those values can be used as general purpose values in special instructions (bound, call...)
    uint32_t address_value;
    uint32_t immediate_value;

    constexpr bool operator==(const Instruction& other) const = default;
};


#endif //COMPUTERTRANSASSEMBLER_INSTRUCTION_H
