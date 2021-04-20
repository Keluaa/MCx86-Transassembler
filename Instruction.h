
#ifndef COMPUTERTRANSASSEMBLER_INSTRUCTION_H
#define COMPUTERTRANSASSEMBLER_INSTRUCTION_H

#include <cstdint>


enum class OpType : uint8_t {
    NONE,
    REG,
    MEM,
    IMM,
    M_M,
    SREG,
    MOFF,
    CREG
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

    bool address_size_override : 1;
    bool operand_size_override : 1;
    bool address_byte_size_override : 1;
    bool operand_byte_size_override : 1;

    bool get_flags : 1;

    OpType op1_type : 3;
    OpType op2_type : 3;

    uint8_t op1_register : 3;
    uint8_t op2_register : 3;

    bool read_op1 : 1;
    bool read_op2 : 1;

    bool write_ret1_to_op1 : 1;
    bool write_ret2_to_op2 : 1;

    bool write_ret1_to_register : 1;
    bool scale_output_override : 1;
    uint8_t register_out : 3;

    bool compute_address : 1;

    uint8_t : 0; // alignment (5 bits of padding)

    // Optional mod r/m and SIB bytes
    union {
        uint16_t raw_address_specifier;
        struct {
            // mod r/m byte
            uint8_t mod:2;
            uint8_t reg:3;
            uint8_t rm:3;

            // SIB byte
            uint8_t scale:2;
            uint8_t index:3;
            uint8_t base:3;
        } mod_rm_sib;
    };

    // both of those values can be used as general purpose values in spacial instructions (bound, call...)
    uint32_t address_value;
    uint32_t immediate_value;


    constexpr bool operator==(const Instruction& other) const
    {
        // We cannot use the default implementation because of the union member.

        if (this == &other) {
            return true;
        }

        // To avoid checking for each bit field and to handle the union we just parse through their bytes.
        // Restrict is used here for pedantry (and optimisations).
        auto* __restrict__ this_bytes = (uint8_t* __restrict__) this;
        auto* __restrict__ other_bytes = (uint8_t* __restrict__) &other;

        for (size_t i = 0; i < sizeof(Instruction); i++, this_bytes++, other_bytes++) {
            if (*this_bytes != *other_bytes) {
                return false;
            }
        }

        return true;
    }
};


#endif //COMPUTERTRANSASSEMBLER_INSTRUCTION_H
