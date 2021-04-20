
#include <cstring>
#include <cassert>

#include "IA32Mapping.h"


/**
 * Converts a string into an int by concatenating their values.
 * Converting a string with more than 8 characters is equivalent to converting the first 8 characters.
 */
static constexpr uint64_t chars_to_int(const char* str)
{
    uint64_t res = 0;
    size_t i = 0;
    for (; str[i] != '\0' && i < 8; i++) {
        res <<= 8;
        res |= str[i];
    }
    return res;
}


static OpType operand_type_from_str(const char* str)
{
    switch (chars_to_int(str)) {
    case chars_to_int("NONE"): return OpType::NONE;
    case chars_to_int("REG"):  return OpType::REG;
    case chars_to_int("MEM"):  return OpType::MEM;
    case chars_to_int("IMM"):  return OpType::IMM;
    case chars_to_int("M_M"):  return OpType::M_M;
    case chars_to_int("SREG"): return OpType::SREG;
    case chars_to_int("MOFF"): return OpType::MOFF;
    case chars_to_int("CREG"): return OpType::CREG;
    default:
        // TODO : better exception handling
        assert(0); // invalid operand type
    }
}


static uint8_t register_index_from_name(const char* name)
{
    switch (chars_to_int(name)) {
    case chars_to_int("A"):  return 0; // EAX, AX, AL
    case chars_to_int("C"):  return 1; // ECX, CX, CL
    case chars_to_int("D"):  return 2; // EDX, DX, DL
    case chars_to_int("B"):  return 3; // EBX, BX, BL
    case chars_to_int("SP"): return 4; // ESP, SP, AH
    case chars_to_int("BP"): return 5; // EBP, BP, CH
    case chars_to_int("SI"): return 6; // ESI, SI, DH
    case chars_to_int("DI"): return 7; // EDI, DI, BH
    default:
        // TODO : better exception handling
        assert(0); // invalid register name
    }
}


static constexpr IA32Operand operand_descriptor_from_str(const char* desc)
{
    switch (chars_to_int(desc)) {
    // Explicit register operands
    case chars_to_int("AL"):       return IA32Operand::AL;
    case chars_to_int("AX"):       return IA32Operand::AX;
    case chars_to_int("EAX"):      return IA32Operand::EAX;

    // Register or memory operands
    case chars_to_int("r/m8"):     return IA32Operand::rm8;
    case chars_to_int("r/m16"):    return IA32Operand::rm16;
    case chars_to_int("r/m32"):    return IA32Operand::rm32;
    case chars_to_int("r/m"):      return IA32Operand::rm;    // r/m16 or r/m32 depending on the register operand

    // Register operands
    case chars_to_int("r8"):       return IA32Operand::r8;
    case chars_to_int("r16"):      return IA32Operand::r16;
    case chars_to_int("r32"):      return IA32Operand::r32;
    case chars_to_int("r"):        return IA32Operand::r;     // r16 or r32 depending on the register operand /r

    // Memory operands
    case chars_to_int("m8"):       return IA32Operand::m8;
    case chars_to_int("m16"):      return IA32Operand::m16;
    case chars_to_int("m32"):      return IA32Operand::m32;
    case chars_to_int("m"):        return IA32Operand::m;     // m16 or m32 depending on the register operand /r

    // Immediate operands
    case chars_to_int("imm8"):     return IA32Operand::imm8;
    case chars_to_int("imm16"):    return IA32Operand::imm16;
    case chars_to_int("imm32"):    return IA32Operand::imm32;
    case chars_to_int("imm"):      return IA32Operand::imm;   // imm16 or imm32 depending on the size

    // Relative address operands
    case chars_to_int("rel8"):     return IA32Operand::rel8;
    case chars_to_int("rel16"):    return IA32Operand::rel16;
    case chars_to_int("rel32"):    return IA32Operand::rel32;
    case chars_to_int("rel"):      return IA32Operand::rel;   // rel16 or rel32 depending on the size

    // Memory offset operands
    case chars_to_int("moffs8"):   return IA32Operand::moffs8;
    case chars_to_int("moffs16"):  return IA32Operand::moffs16;
    case chars_to_int("moffs32"):  return IA32Operand::moffs32;
    case chars_to_int("moffs"):    return IA32Operand::moffs; // moffs16 or moffs32 depending on the size

    // Far pointer operands
    case chars_to_int("ptr16_16"): return IA32Operand::ptr16_16;
    case chars_to_int("ptr16_32"): return IA32Operand::ptr16_32;

    // Far memory operands
    case chars_to_int("m16_16"):   return IA32Operand::m16_16;
    case chars_to_int("m16_32"):   return IA32Operand::m16_32;

    // Double memory operands
    case chars_to_int("m16&32"):   return IA32Operand::m16$32;
    case chars_to_int("m16&16"):   return IA32Operand::m16$16;
    case chars_to_int("m32&32"):   return IA32Operand::m16$32;

    // Segment register operands
    case chars_to_int("Sreg"):     return IA32Operand::Sreg;

    default:
        assert(0);
    }
}


void IA32Mapping::load_instruction_mapping(std::fstream& mapping_file)
{
    // skip the header row
    mapping_file.ignore(512, '\n');

    IA32Inst inst{};
    uint16_t full_opcode;

    bool b1, b2, b3, b4, b5, b6;
    char op_type[5];

    while (!mapping_file.eof() && mapping_file.good()) {
        mapping_file.get(inst.mnemonic, 5, ',');
        mapping_file.ignore(1); // skip the comma

        mapping_file >> std::hex >> full_opcode >> inst.equiv_opcode >> std::dec;
        if (full_opcode & 0xFF00) {
            inst.opcode = (full_opcode & 0xFF00) >> 8;
            inst.opcode_ext = full_opcode & 0x00FF;
        }
        else {
            inst.opcode = full_opcode;
        }

        mapping_file >> std::noboolalpha
                     >> b1 >> b2 >> b3 >> b4 >> b5;
        inst.keep_overrides = b1;
        inst.address_size_override = b2;
        inst.operand_size_override = b3;
        inst.address_byte_size_override = b4;
        inst.operand_byte_size_override = b5;

        mapping_file.get(op_type, 5, ',');
        mapping_file.ignore(1); // skip the comma
        inst.operand_1_type = operand_type_from_str(op_type);

        mapping_file.get(op_type, 5, ',');
        mapping_file.ignore(1); // skip the comma
        inst.operand_2_type = operand_type_from_str(op_type);

        mapping_file.get(op_type, 3, ',');
        mapping_file.ignore(1); // skip the comma
        inst.operand_1_register = register_index_from_name(op_type);

        mapping_file.get(op_type, 3, ',');
        mapping_file.ignore(1); // skip the comma
        inst.operand_2_register = register_index_from_name(op_type);

        mapping_file >> b1 >> b2 >> b3 >> b4 >> b5 >> b6;
        inst.read_operand_1 = b1;
        inst.read_operand_2 = b2;
        inst.write_ret_1_to_op_1 = b3;
        inst.write_ret_2_to_op_2 = b4;
        inst.write_ret_1_register = b5;
        inst.write_ret_1_register_scale = b5;

        mapping_file.get(op_type, 3, ',');
        mapping_file.ignore(1); // skip the comma
        if (inst.write_ret_1_register) {
            inst.write_ret_1_out_register = register_index_from_name(op_type);
        }
        else {
            inst.write_ret_1_out_register = 0;
        }

        mapping_file >> b1 >> b2 >> b3 >> b4;
        inst.compute_address = b1;
        inst.has_mod_SIB = b2;
        inst.extract_immediate_address = b3;
        inst.constant_immediate_value = b4;

        if (inst.constant_immediate_value) {
            mapping_file >> inst.immediate_value;
        }
        else {
            inst.immediate_value = 0;
        }

        if (IA32_instructions.contains(full_opcode)) {
            printf("Duplicate opcode: %d (%s)\n", full_opcode, inst.mnemonic);
        }
        else {
            IA32_instructions.insert(std::pair<uint16_t, const IA32Inst>(full_opcode, inst));
        }
    }
}


bool IA32Mapping::extract_instruction(const ZydisDecodedInstruction& IA32inst, Instruction& inst) const
{
    if (!IA32_instructions.contains(IA32inst.opcode)) {
        printf("Unknown opcode: %d (%s)\n", IA32inst.opcode, ZydisMnemonicGetString(IA32inst.mnemonic));
        return false;
    }

    const IA32Inst& extract_data = IA32_instructions.at(IA32inst.opcode);

    inst.opcode = extract_data.equiv_opcode;

    if (extract_data.keep_overrides) {
        inst.address_size_override = IA32inst.address_width == 2;       // 16-bit override
        inst.address_byte_size_override = IA32inst.address_width == 1;  // 8-bit override

        inst.operand_size_override = IA32inst.operand_width == 2;       // 16-bit override
        inst.operand_byte_size_override = IA32inst.operand_width == 1;  // 8-bit override
    }
    else {
        inst.address_size_override = extract_data.address_size_override;
        inst.address_byte_size_override = extract_data.address_byte_size_override;

        inst.operand_size_override = extract_data.operand_size_override;
        inst.operand_byte_size_override = extract_data.operand_byte_size_override;
    }

    inst.op1_type = extract_data.operand_1_type;
    inst.op2_type = extract_data.operand_2_type;

    inst.op1_register = extract_data.operand_1_register;
    inst.op2_register = extract_data.operand_2_register;

    inst.read_op1 = extract_data.read_operand_1;
    inst.read_op2 = extract_data.read_operand_2;

    inst.write_ret1_to_op1 = extract_data.write_ret_1_to_op_1;
    inst.write_ret2_to_op2 = extract_data.write_ret_2_to_op_2;

    if (extract_data.write_ret_1_register) {
        inst.write_ret1_to_register = true;
        inst.scale_output_override = extract_data.write_ret_1_register_scale;
        inst.register_out = extract_data.write_ret_1_out_register;
    }
    else {
        inst.write_ret1_to_register = false;
        inst.scale_output_override = false;
        inst.register_out = 0;
    }

    inst.compute_address = extract_data.compute_address;

    if (extract_data.has_mod_SIB) {
        // Extract the Mod r/m byte data

        // TODO : add extract data fields: /r flag present, and if it is for the first or second operand
        //  r/m operand present, and if it is for the first or second operand (maybe deductible from the same value of the /r flag)
        //  also other special memory operands should have a r/m presence flag

        if (extract_data.reg_and_rm_operands) {
            if (/* /r flag for first operand */ 1) {
                inst.op1_type = OpType::REG;
                inst.op1_register = IA32inst.raw.modrm.reg;
            }
            else {
                inst.op2_type = OpType::REG;
                inst.op2_register = IA32inst.raw.modrm.reg;
            }
        }

        if (/* r/m operand present */ 1) {
            if (IA32inst.raw.modrm.mod == 0b11) {
                // This Mod r/m byte is specifying a register operand
                if (/* /r flag for first operand */ 1) {
                    // Then the r/m operand is the second one
                    inst.op2_type = OpType::REG;
                    inst.op2_register = IA32inst.raw.modrm.rm;
                }
                else {
                    // Then the r/m operand is the first one
                    inst.op1_type = OpType::REG;
                    inst.op1_register = IA32inst.raw.modrm.rm;
                }
            }
            else {
                // Advanced memory operand
                inst.mod_rm_sib.mod = IA32inst.raw.modrm.mod;
                inst.mod_rm_sib.reg = IA32inst.raw.modrm.reg;
                inst.mod_rm_sib.rm = IA32inst.raw.modrm.rm;

                if (IA32inst.raw.modrm.rm == 0b100) {
                    // Extract the SIB byte
                    inst.mod_rm_sib.scale = IA32inst.raw.sib.scale;
                    inst.mod_rm_sib.index = IA32inst.raw.sib.index;
                    inst.mod_rm_sib.base = IA32inst.raw.sib.base;
                }

                inst.compute_address = true; // In this case we must be computing the address
            }
        }
    }
    else {
        inst.raw_address_specifier = 0; // Set the whole Mod r/m + SIB to 0
    }

    // TODO : there is more work required for address offsets

    inst.immediate_value = IA32inst.raw.imm[0].value.u;
    inst.address_value = IA32inst.raw.imm[1].value.u; // TODO : or IA32inst.raw.disp ? => more checks to do

    return true;
}
