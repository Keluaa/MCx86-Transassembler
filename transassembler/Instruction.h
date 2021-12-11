
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
 * Total size: 107 bits used.
 */
struct Instruction {

    uint8_t opcode;

    // Struct describing an operand, present in order for IA32::Mapping::convert_operand to exist.
    struct Operand {
        OpType type : 2;
        Register reg : 5;
        bool read : 1;

        /*constexpr*/ bool operator==(const Operand& other) const = default; // TODO : re-enable constexpr when the GCC bug is fixed
    } op1, op2;

    // TODO : docs for all fields

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

    /*
        Addressing

    In IA-32, the following addressing modes are possible (in 32 bit addressing):
      mod r/m index  base               effective address
      11  ...                                    base reg
      00  101                                               displacement
      00  ...                                    base reg
      ..  ...                                    base reg + displacement
      ..  100  100   ...                         base reg + displacement
      ..  100  ...   ...    scaled reg * scale + base reg + displacement
      00  100  ...   101    scaled reg * scale +          + displacement
      ..  100  ...   101    scaled reg * scale +   EBP    + displacement

    The base register is always a 32 bit register index, unless Mod = 11, in which case it is an operand and so scaled
    according to the operand size overrides.
    The scaled register is always a 32 bit register index.
    Displacement is a signed value of either 8 bits or 32 bits.
    The scale is encoded in 2 bits as follows: '0b00' -> 1, '0b01' -> 2, '0b10' -> 4, '0b11' -> 8

    Here we encode those addressing modes this way:
      - base reg     : stored as a register index in the 3 low bits of the 'reg' field of the operand of type memory
      - scaled reg   : stored explicitly in the 'scaled_reg' field
      - scale        : stored in the high 2 bits of the 'reg' field of the operand of type memory
      - displacement : stored as a 32 bit value. 8 bit displacements are sign-extended to 32 bit.

    Then to compute the address, the following flags are used to indicate the presence of a field :
      - base_reg_present   : if the 'reg' field of the memory operand has a register index
      - scaled_reg_present : if the 'scaled_reg' field has a register index

    If 'compute_address' is true, then it is computed according to the following formula. Any absent field is replaced
    by zero.
                base_reg + scaled_reg * scale + displacement

    If 'compute_address' is false, then only the base register is loaded.
     */
    bool compute_address : 1;
    bool base_reg_present : 1;
    bool scaled_reg_present : 1;
    uint8_t scaled_reg : 3;

    uint8_t : 0;

    uint32_t address_value; // Holds an address displacement value or an immediate constant address
    uint32_t immediate_value;

    // The Operand struct by itself cannot describe when it is not used, here is how to do it for both operands:
    [[nodiscard]] constexpr bool is_op1_none() const { return !op1.read && !write_ret1_to_op1; }
    [[nodiscard]] constexpr bool is_op2_none() const { return !op2.read && !write_ret2_to_op2; }

    /*constexpr*/ bool operator==(const Instruction& other) const = default; // TODO : re-enable constexpr when the GCC bug is fixed
};


#endif //COMPUTERTRANSASSEMBLER_INSTRUCTION_H
