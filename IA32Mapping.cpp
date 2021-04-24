
#include <cstring>
#include <charconv>
#include <array>
#include <any>

#include "IA32Mapping.h"


/**
 * Alternative to sscanf, with optional formats.
 *
 * This exists because streams don't support delimiters (or formatted input), and formats don't support optional
 * arguments in general.
 * Supports:
 *  - '%b' booleans conversion from a numerical value (value type: bool*)
 *  - '%d' decimal integer conversion (value type: [unsigned] int*)
 *  - '%x' hexadecimal integer conversion (value type: [unsigned] int*)
 *  - '%s' strings, of any length (value type: std::string*)
 *
 * Strings formats extracts all characters to the next character of the format (it must not be another conversion: '%<any>')
 * or the end of the input string. If '%s' is at the end of the format string, all characters of the rest of the input
 * string are extracted.
 *
 * @param str The formatted string to extract data from
 * @param format The format string
 * @param args Array of std::any of either bool*, uint32_t* or std::string*. They should point to the default values of
 *  the format
 * @return The number of characters extracted from the input string, or -1 if there was an error
 */
template<size_t N>
int scan_optional_format(const std::string& str, const char* format, const std::array<std::any, N>& args)
{
    size_t args_index = 0;

    std::from_chars_result status{};
    status.ptr = str.c_str();

    const char* str_end = str.c_str() + str.length();

    int value;

    char format_c;
    while ((format_c = *format++) != '\0'
           && args_index < N
           && status.ptr != str_end) {
        if (format_c == '%') {
            switch(*format++) {
            case '\0':
            default:
                // Wrong format
                return -1;

            case 'b': // boolean
                if (*status.ptr == *format) {
                    // The next character in the string is the character after %b -> skip this argument
                    args_index++;
                    continue;
                }
                status = std::from_chars(status.ptr, str_end, value);
                if (status.ec != std::errc()) {
                    // Conversion error
                    return -1;
                }
                *std::any_cast<bool*>(args.at(args_index)) = (bool) value;
                break;

            case 'd': // decimal number
                if (*status.ptr == *format) {
                    // The next character in the string is the character after %d -> skip this argument
                    args_index++;
                    continue;
                }
                status = std::from_chars(status.ptr, str_end, value);
                if (status.ec != std::errc()) {
                    // Conversion error
                    return -1;
                }
                *std::any_cast<uint32_t*>(args.at(args_index)) = value;
                break;

            case 'x': // hexadecimal number
                if (*status.ptr == *format) {
                    // The next character in the string is the character after %x -> skip this argument
                    args_index++;
                    continue;
                }
                status = std::from_chars(status.ptr, str_end, value, 16);
                if (status.ec != std::errc()) {
                    // Conversion error
                    return -1;
                }
                *std::any_cast<uint32_t*>(args.at(args_index)) = value;
                break;

            case 's': // string
            {
                // We parse the string until we find the next character of the format, or the end of it.
                const char* string_start = status.ptr;
                const char* string_end = string_start;
                const char next_format_char = *format;
                if (next_format_char == '%') {
                    return -1; // malformed format
                }

                while (*string_end != '\0' && *string_end != next_format_char) { string_end++; }

                std::string new_string(string_start, string_end - string_start);
                *std::any_cast<std::string*>(args.at(args_index)) = std::move(new_string);

                status.ptr = string_end;
                break;
            }
            }
            args_index++;
        }
        else {
            // Try to match the character
            if (*status.ptr++ != format_c) {
                return -1;
            }
        }
    }

    // The last 'status.ptr' value should point to the character before the '\0'
    return int((status.ptr + 1) - str_end);
}


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


static constexpr uint8_t register_index_from_name(const char* name)
{
    switch (chars_to_int(name)) {
    case 0: // no register -> 0
    case chars_to_int("A"):  return 0; // EAX, AX, AL
    case chars_to_int("C"):  return 1; // ECX, CX, CL
    case chars_to_int("D"):  return 2; // EDX, DX, DL
    case chars_to_int("B"):  return 3; // EBX, BX, BL
    case chars_to_int("SP"): return 4; // ESP, SP, AH
    case chars_to_int("BP"): return 5; // EBP, BP, CH
    case chars_to_int("SI"): return 6; // ESI, SI, DH
    case chars_to_int("DI"): return 7; // EDI, DI, BH
    default:
        throw IA32::LoadingException("Invalid register name: '%s'", name);
    }
}


static constexpr IA32::Operand operand_descriptor_from_str(const char* desc)
{
    switch (chars_to_int(desc)) {

    case 0:
    case chars_to_int("NONE"):
    case chars_to_int("None"):
    case chars_to_int("none"):
        return IA32::Operand::None;

    // Explicit register operands
    case chars_to_int("AL"):       return IA32::Operand::AL;
    case chars_to_int("AX"):
    case chars_to_int("EAX"):      return IA32::Operand::EAX;   // AX or EAX depending on the operand size

    // Implicit register operands, encoded into the opcode
    case chars_to_int("reg"):      return IA32::Operand::reg;   // reg16 or reg32 depending on the operand size
    case chars_to_int("reg8"):     return IA32::Operand::reg8;

        // Register or memory operands
    case chars_to_int("r/m"):      return IA32::Operand::rm;    // r/m16 or r/m32 depending on the operand size
    case chars_to_int("r/m8"):     return IA32::Operand::rm8;


    // Register operands
    case chars_to_int("r"):        return IA32::Operand::r;     // r16 or r32 depending on the operand size
    case chars_to_int("r8"):       return IA32::Operand::r8;

    // Memory operands
    case chars_to_int("m"):        return IA32::Operand::m;     // m16 or m32 depending on the operand size
    case chars_to_int("m8"):       return IA32::Operand::m8;

    // Immediate operands
    case chars_to_int("imm8"):     return IA32::Operand::imm8;
    case chars_to_int("imm16"):    return IA32::Operand::imm16;
    case chars_to_int("imm32"):    return IA32::Operand::imm32;    // imm16 or imm32 depending on the operand size

    // Relative address operands
    case chars_to_int("rel"):      return IA32::Operand::rel;      // rel8, rel16 or rel32 depending on the operand size

    // Memory offset operands
    case chars_to_int("moffs"):    return IA32::Operand::moffs;    // moffs8, moffs16 or moffs32 depending on the operand size

    // Far pointer operands
    case chars_to_int("ptr16_32"): return IA32::Operand::ptr16_32; // ptr16_32 or ptr16_16 depending on the operand size

    // Far memory operands
    case chars_to_int("m16_32"):   return IA32::Operand::m16_32;   // m16_32 or m16_16 depending on the operand size

    // Double memory operands
    case chars_to_int("m16&32"):   return IA32::Operand::m16$32;
    case chars_to_int("m32&32"):   return IA32::Operand::m32$32;   // m16_32 or m16_16 depending on the operand size

    // Segment register operands
    case chars_to_int("Sreg"):     return IA32::Operand::Sreg;

    default:
        throw IA32::LoadingException("Invalid operand descriptor: '%s'", desc);
    }
}


/**
 * Returns true if the instruction has a Mod r/m byte.
 *
 * @param digit_flag_present If the opcode is extended by the reg part of the Mod r/m byte, symbolised by a /digit in
 *  the manual
 * @param first_operand First operand of the instruction
 * @param second_operand Second operand of the instruction
 */
static constexpr bool is_mod_rm_byte_present(bool digit_flag_present, IA32::Operand first_operand, IA32::Operand second_operand)
{
    if (digit_flag_present) {
        return true;
    }

    for (auto&& operand : {first_operand, second_operand}) {
        switch (first_operand) {
        case IA32::Operand::r:
        case IA32::Operand::r8:
        case IA32::Operand::m:
        case IA32::Operand::m8:
        case IA32::Operand::rm:
        case IA32::Operand::rm8:
            return true;

        default:
            break;
        }
    }

    return false;
}


/**
 * In the case where the Mod part of the Mod r/m byte is different than 0b11, using the value of the r/m part of the
 * Mod r/m byte of an encoded instruction, returns true if there is an SIB byte.
 *
 * @param address_size_override Value of the address size override prefix
 * @param rm_value Value of the r/m part of the Mod r/m byte
 */
static constexpr bool is_sib_byte_present(bool address_size_override, uint8_t rm_value)
{
    if (address_size_override) {
        // No SIB byte in 16 bit addressing mode.
        // We suppose that all segments use 32 bit addressing, meaning that the address size override prefix implies 16
        // bit addressing.
        return false;
    }

    // By the manual, there is an SIB byte if: r/m = 0b100 and Mod = anything but 0b11
    return rm_value == 0b100;
}


/**
 * Parses the CSV file containing the information on how to extract the data needed for each instruction of the IA-32
 * ABI.
 *
 * @param mapping_file CSV file
 *
 * Structure of the CSV file (the first line is the header):
 * (opcodes)
 *  - Mnemonic (string)
 *  - Opcode (hex string)
 *  - Opcode extension (decimal string)
 *  - /digit flag (bool string), indicates that the reg field of the Mod r/m byte is used to extend the opcode, the
 *    value of the field specifies the value of the extension
 *  - generate for all registers flag (bool string), indicates that the same instruction definition is repeated for each
 *    8 registers, with the register included in the opcode by adding its index to the base opcode given
 *  - Equivalent mnemonic in the new instruction set (string)
 * (size overrides)
 *  - Keep address and operand size overrides (bool string)
 *  - Address size override to 16 bits (bool string)
 *  - Operand size override to 16 bits (bool string)
 * (operands)
 *  - First operand type (string, see operand_descriptor_from_str)
 *  - Second operand type (string, see operand_descriptor_from_str)
 *  - Has an additional immediate operand (bool string)
 * (input)
 *  - Read first operand (bool string)
 *  - Read second operand (bool string)
 * (output)
 *  - Write first result to first operand (bool string)
 *  - Write second result to second operand (bool string)
 *  - Write first result to specific register (bool string)
 *  - Scale the specific register with the size overrides (bool string)
 *  - First result register (string, see register_index_from_name)
 */
bool IA32::Mapping::load_instructions_extract_info(std::fstream& mapping_file, const ComputerOpcodesInfo& opcodes_info)
{
    // skip the header row
    mapping_file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    IA32::Inst inst{};

    char line_buffer[512] = "";
    std::string line;

    std::string tmp_equiv_mnemonic, tmp_operand_1, tmp_operand_2, tmp_r1_reg;
    tmp_equiv_mnemonic.reserve(10);
    tmp_operand_1.reserve(10);
    tmp_operand_2.reserve(10);
    tmp_r1_reg.reserve(10);

    uint32_t tmp_opcode;
    uint32_t extension;

    bool repeat_for_all_registers;
    bool tmp_keep_overrides, tmp_address_override, tmp_operand_override;
    bool tmp_opt_immediate, tmp_read_op1, tmp_read_op2, tmp_write_r1_op1, tmp_write_r2_op2;
    bool tmp_write_r1_reg, tmp_r1_reg_scale;

    const std::array format_values{
            std::make_any<uint32_t*>(&tmp_opcode),
            std::make_any<uint32_t*>(&extension),
            std::make_any<bool*>(&repeat_for_all_registers),
            std::make_any<std::string*>(&tmp_equiv_mnemonic),
            std::make_any<bool*>(&tmp_keep_overrides),
            std::make_any<bool*>(&tmp_address_override),
            std::make_any<bool*>(&tmp_operand_override),
            std::make_any<std::string*>(&tmp_operand_1),
            std::make_any<std::string*>(&tmp_operand_2),
            std::make_any<bool*>(&tmp_opt_immediate),
            std::make_any<bool*>(&tmp_read_op1),
            std::make_any<bool*>(&tmp_read_op2),
            std::make_any<bool*>(&tmp_write_r1_op1),
            std::make_any<bool*>(&tmp_write_r2_op2),
            std::make_any<bool*>(&tmp_write_r1_reg),
            std::make_any<bool*>(&tmp_r1_reg_scale),
            std::make_any<std::string*>(&tmp_r1_reg),
    };

    int line_nb = 0;

    while (mapping_file.good()) {
        mapping_file.get(inst.mnemonic, 6, ',');
        mapping_file.ignore(1); // skip the comma

        if (mapping_file.eof()) {
            break;
        }

        mapping_file.getline(line_buffer, 512);
        line.assign(line_buffer);

        // Set all optional values to their default value
        extension = 0;
        repeat_for_all_registers = false;
        tmp_keep_overrides = true;
        tmp_address_override = false;
        tmp_operand_override = false;
        tmp_opt_immediate = false;
        tmp_read_op1 = false;
        tmp_read_op2 = false;
        tmp_write_r1_op1 = false;
        tmp_write_r2_op2 = false;
        tmp_write_r1_reg = false;
        tmp_r1_reg_scale = false;
        tmp_operand_1.clear();
        tmp_operand_2.clear();
        tmp_r1_reg.clear();

        // Scan the line
        const char format[] = "%x,%d,%b,%s,%b,%b,%b,%s,%s,%b,%b,%b,%b,%b,%b,%b,%s\r";
        if (scan_optional_format(line, format, format_values)) {
            // Not all of the line has been parsed
            throw LoadingException("Invalid characters at line %d", line_nb);
        }

        // The two non-optional values
        inst.opcode = tmp_opcode;
        strcpy(inst.equiv_mnemonic, tmp_equiv_mnemonic.c_str());

        // Handle opcode extensions
        if (extension != 0) {
            opcodes_with_reg_extension.insert(inst.opcode);
            inst.opcode += extension << 12;
        }

        // Optional values
        inst.keep_overrides = tmp_keep_overrides;
        inst.address_size_override = tmp_address_override;
        inst.operand_size_override = tmp_operand_override;
        inst.operand_1 = operand_descriptor_from_str(tmp_operand_1.c_str());
        inst.operand_2 = operand_descriptor_from_str(tmp_operand_2.c_str());
        inst.has_immediate_operand = tmp_opt_immediate;
        inst.read_operand_1 = tmp_read_op1;
        inst.read_operand_2 = tmp_read_op2;
        inst.write_ret_1_to_op_1 = tmp_write_r1_op1;
        inst.write_ret_2_to_op_2 = tmp_write_r2_op2;
        inst.write_ret_1_register = tmp_write_r1_reg;
        inst.write_ret_1_register_scale = tmp_r1_reg_scale;
        inst.write_ret_1_out_register = register_index_from_name(tmp_r1_reg.c_str());

        inst.has_mod_byte = is_mod_rm_byte_present(extension != 0, inst.operand_1, inst.operand_2);

        ComputerOpcodesInfo::OpcodeInfo opcode_info = opcodes_info.get_infos(inst.equiv_mnemonic);
        inst.equiv_opcode = opcode_info.opcode;
        inst.get_flags = opcode_info.get_flags;

        if (repeat_for_all_registers) {
            // Generate the same instruction (with different opcodes) for all 8 general purpose registers.
            for (int i = 0; i < 8; i++) {
                IA32::Inst copy = inst;
                copy.opcode += i;

                if (instructions_extraction_info.contains(copy.opcode)) {
                    throw LoadingException("Duplicate opcode: 0x%x", copy.opcode);
                }

                instructions_extraction_info.insert(std::pair<uint16_t, const IA32::Inst>(copy.opcode, copy));
            }
        }
        else {
            if (instructions_extraction_info.contains(inst.opcode)) {
                throw LoadingException("Duplicate opcode: 0x%x", inst.opcode);
            }

            instructions_extraction_info.insert(std::pair<uint16_t, const IA32::Inst>(inst.opcode, inst));
        }

        line_nb++;
    }

    return false;
}


/**
 * Extracts the data from the IA-32 instruction to create its equivalent in our instruction set.
 *
 * Because the next step will make all instructions have the same size, addresses in the code segment needs to be
 * fixed and absolute. To prepare for this we:
 *  - convert memory offsets to absolute addresses
 *  - check if dynamic address indexing operands use the code segment, and raise an error if it is
 *
 * @param IA32inst The instruction to convert
 * @param inst The resulting instruction
 * @param virtual_address Current address of the beginning of the encoded instruction
 * @param segment_base_address Base address of the code segment
 */
void IA32::Mapping::convert_instruction(const ZydisDecodedInstruction& IA32inst, Instruction& inst,
                                        uint32_t virtual_address, uint32_t segment_base_address) const
{
    if (!instructions_extraction_info.contains(IA32inst.opcode)) {
        throw ConversionException(virtual_address, "Unknown opcode: %d (%s)\n", IA32inst.opcode, ZydisMnemonicGetString(IA32inst.mnemonic));
    }

    // TODO : REP prefix, checked with IA32inst.attributes & ZYDIS_ATTRIB_HAS_REP ou ZYDIS_ATTRIB_HAS_REPE

    uint16_t opcode = IA32inst.opcode;
    opcode |= IA32inst.opcode_map == ZYDIS_OPCODE_MAP_0F ? 0x0F00 : 0x0000;
    if (opcodes_with_reg_extension.contains(IA32inst.opcode)) {
        // /digit extension from the reg field of the Mod r/m byte
        opcode += IA32inst.raw.modrm.reg << 12;
    }

    const IA32::Inst& extract_data = instructions_extraction_info.at(opcode);

    inst.opcode = extract_data.equiv_opcode;

    // Size overrides
    if (extract_data.keep_overrides) {
        inst.address_size_override = IA32inst.address_width == 16; // 16-bits override
        inst.operand_size_override = IA32inst.operand_width == 16; // 16-bits override
    }
    else {
        inst.address_size_override = extract_data.address_size_override;
        inst.operand_size_override = extract_data.operand_size_override;
    }

    // Mod r/m and SIB bytes
    // TODO : check if the resulting address is located into the code segment, and report the error if it is
    //  also the segment prefixes are NOT taken into account, which is really bad
    bool rm_is_register_operand = false;
    uint8_t register_index = 0;
    if (extract_data.has_mod_byte) {
        if (IA32inst.raw.modrm.mod == 0b11) {
            // The Mod r/m byte describes a register operand
            rm_is_register_operand = true;
            register_index = IA32inst.raw.modrm.rm;
        }
        else if (inst.address_size_override) {
            throw ConversionException(virtual_address, "16-bits addressing with the Mod r/m byte is not implemented.");
        }
        else if (IA32inst.raw.modrm.mod == 0b00 && IA32inst.raw.modrm.rm == 0b101) {
            // Mod r/m byte, alone with no register. There is only a displacement
            inst.displacement_present = true;

            // Extract the displacement value
            inst.address_value = IA32inst.raw.disp.value;
        }
        else {
            // The Mod r/m byte describes a memory operand

            if (is_sib_byte_present(inst.address_size_override, IA32inst.raw.modrm.rm)) {
                inst.reg_present = true;
                inst.reg = IA32inst.raw.sib.index;
                inst.scale = IA32inst.raw.sib.scale;

                if (IA32inst.raw.sib.base == 0b101 && IA32inst.raw.modrm.mod == 0b00) {
                    inst.base_present = false;
                }
                else {
                    inst.base_present = true;
                    inst.base_reg = IA32inst.raw.sib.base;
                }
            }
            else {
                // Mod r/m byte alone
                inst.reg_present = true;
                inst.reg = IA32inst.raw.modrm.rm;
            }

            // Displacement
            switch (IA32inst.raw.modrm.mod) {
            case 0b00:
                inst.displacement_present = false;
                break;

            case 0b01:
                inst.displacement_present = true;
                // 8 bits displacement
                inst.address_value = (int32_t) ((int8_t) ((uint8_t) IA32inst.raw.disp.value));
                break;

            case 0b10:
                inst.displacement_present = true;
                // 32 bits displacement
                inst.address_value = IA32inst.raw.disp.value;
                break;
            }
        }
    }

    if (extract_data.has_mod_byte != bool(IA32inst.attributes & ZYDIS_ATTRIB_HAS_MODRM)) {
        // TODO : remove if unnecessary
        throw ConversionException(virtual_address, "Invalid implementation, extraction info is different from the one of the decompiler.");
    }

    // First operand
    switch (extract_data.operand_1) {
    default:
    case IA32::Operand::None:
        break;

    case Operand::AL:
        inst.operand_byte_size_override = true;
    case Operand::EAX:
        inst.op1_type = OpType::REG;
        inst.op1_register = Register::EAX;
        break;

    case Operand::reg8:
        inst.operand_byte_size_override = true;
    case Operand::reg:
        inst.op1_type = OpType::REG;
        inst.op1_register = Register(inst.opcode & 0b111); // The register index is encoded in the first 3 bits of the opcode
        break;

    case Operand::r8:
        inst.operand_byte_size_override = true;
    case Operand::r:
        inst.op1_type = OpType::REG;
        inst.op1_register = Register(ZydisRegisterGetId(IA32inst.operands[0].reg.value));
        break;

    case Operand::rm8:
        inst.operand_byte_size_override = true;
    case Operand::rm:
        if (rm_is_register_operand) {
            inst.op1_type = OpType::REG;
            inst.op1_register = Register(register_index);
        }
        else {
            // Memory operand
            inst.op1_type = OpType::MEM;
        }
        break;

    case Operand::m8:
        inst.operand_byte_size_override = true;
    case Operand::m:
        inst.op1_type = OpType::MEM;
        break;

        // For each immediate value, we only keep the bytes we are interested in, without sign-extending the value.
    case Operand::imm8:
        inst.op1_type = OpType::IMM;
        inst.immediate_value = (uint8_t) IA32inst.operands[0].imm.value.u;
        break;

    case Operand::imm16:
        inst.op1_type = OpType::IMM;
        inst.immediate_value = (uint16_t) IA32inst.operands[0].imm.value.u;
        break;

    case Operand::imm32:
        inst.op1_type = OpType::IMM;
        inst.immediate_value = (uint32_t) IA32inst.operands[0].imm.value.u;
        break;

        // For memory offsets operands, we compute the actual virtual address here
        // TODO : check if the calculations are not off by one
    case Operand::rel:
        inst.op1_type = OpType::ABS_MEM;
        // Signed offset relative to the end of the instruction
        inst.address_value = virtual_address + IA32inst.length + IA32inst.operands[0].imm.value.s;
        break;

    case Operand::moffs:
        inst.op1_type = OpType::ABS_MEM;
        // Unsigned offset relative to the current segment
        inst.address_value = segment_base_address + IA32inst.operands[0].imm.value.u;
        break;

    case Operand::ptr16_32:
        // Far pointer to another code segment
        // TODO : the far pointer may also point to the same code segment, in which case we can use its offset as an
        //  offset to the base segment address, and the instruction can be converted.
        // We cannot jump to other segments, since there should only be one code segment.
        throw ConversionException(virtual_address, "Invalid operand type: far pointers should not exist since there should be only one text segment.");

    case Operand::m16_32:
        // Far pointer to another segment
        // TODO ?
        throw ConversionException(virtual_address, "Invalid operand type: far pointers to segments other than code segments are not yet supported.");

    case Operand::m16$32:
        // Limit and base field of segment descriptors
        // TODO ?
        throw ConversionException(virtual_address, "Invalid operand type: m16&32 is not yet implemented.");

    case Operand::m32$32:
        // Double memory operand
        // TODO ? (only for BOUND, the least used instruction)
        throw ConversionException(virtual_address, "Invalid operand type: m32&32 (or m16&16) is not yet implemented.");

    case Operand::Sreg:
        // Segment register index
        inst.op1_type = OpType::SREG;
        inst.op1_register = Register(ZydisRegisterGetId(IA32inst.operands[0].reg.value));
        break;
    }

    // Second operand
    switch (extract_data.operand_2) {
    default:
    case IA32::Operand::None:
        break;

    case Operand::AL:
        if (!inst.operand_byte_size_override) {
            throw ConversionException(virtual_address, "The implementation is maybe wrong, since the previous operand doesn't have a byte size override.");
        }
    case Operand::EAX:
        inst.op2_type = OpType::REG;
        inst.op2_register = Register::EAX;
        break;

    case Operand::reg8:
        if (!inst.operand_byte_size_override) {
            throw ConversionException(virtual_address, "The implementation is maybe wrong, since the previous operand doesn't have a byte size override.");
        }
    case Operand::reg:
        inst.op2_type = OpType::REG;
        inst.op2_register = Register(inst.opcode & 0b111); // The register index is encoded in the first 3 bits of the opcode
        break;

    case Operand::r8:
        if (!inst.operand_byte_size_override) {
            throw ConversionException(virtual_address, "The implementation is maybe wrong, since the previous operand doesn't have a byte size override.");
        }
    case Operand::r:
        inst.op2_type = OpType::REG;
        inst.op2_register = Register(ZydisRegisterGetId(IA32inst.operands[1].reg.value));
        break;

    case Operand::rm8:
        if (!inst.operand_byte_size_override) {
            throw ConversionException(virtual_address, "The implementation is maybe wrong, since the previous operand doesn't have a byte size override.");
        }
    case Operand::rm:
        if (rm_is_register_operand) {
            inst.op2_type = OpType::REG;
            inst.op2_register = Register(register_index);
        }
        else {
            // Memory operand
            inst.op2_type = OpType::MEM;
        }
        break;

    case Operand::m8:
        if (!inst.operand_byte_size_override) {
            throw ConversionException(virtual_address, "The implementation is maybe wrong, since the previous operand doesn't have a byte size override.");
        }
    case Operand::m:
        inst.op2_type = OpType::MEM;
        break;

        // For each immediate value, we only keep the bytes we are interested in, without sign-extending the value.
    case Operand::imm8:
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "The implementation is wrong, since the previous operand also used an immediate value.");
        }
        inst.op2_type = OpType::IMM;
        inst.immediate_value = (uint8_t) IA32inst.operands[1].imm.value.u;
        break;

    case Operand::imm16:
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "The implementation is wrong, since the previous operand also used an immediate value.");
        }
        inst.op2_type = OpType::IMM;
        inst.immediate_value = (uint16_t) IA32inst.operands[1].imm.value.u;
        break;

    case Operand::imm32:
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "The implementation is wrong, since the previous operand also used an immediate value.");
        }
        inst.op2_type = OpType::IMM;
        inst.immediate_value = (uint32_t) IA32inst.operands[1].imm.value.u;
        break;

        // For memory offsets operands, we compute the actual virtual address here
        // TODO : check if the calculations are not off by one
    case Operand::rel:
        if (inst.address_value != 0) {
            throw ConversionException(virtual_address, "The implementation is wrong, since the previous operand also used an address value.");
        }
        inst.op2_type = OpType::ABS_MEM;
        // Signed offset relative to the end of the instruction
        inst.address_value = virtual_address + IA32inst.length + IA32inst.operands[1].imm.value.s;
        break;

    case Operand::moffs:
        if (inst.address_value != 0) {
            throw ConversionException(virtual_address, "The implementation is wrong, since the previous operand also used an address value.");
        }
        inst.op2_type = OpType::ABS_MEM;
        // Unsigned offset relative to the current segment
        inst.address_value = segment_base_address + IA32inst.operands[1].imm.value.u;
        break;

    case Operand::ptr16_32:
        // Far pointer to another code segment
        // TODO : the far pointer may also point to the same code segment, in which case we can use its offset as an
        //  offset to the base segment address, and the instruction can be converted.
        // We cannot jump to other segments, since there should only be one code segment.
        throw ConversionException(virtual_address, "Invalid operand type: far pointers should not exist since there should be only one text segment.");

    case Operand::m16_32:
        // Far pointer to another segment
        // TODO ?
        throw ConversionException(virtual_address, "Invalid operand type: far pointers to segments other than code segments are not yet supported.");

    case Operand::m16$32:
        // Limit and base field of segment descriptors
        // TODO ?
        throw ConversionException(virtual_address, "Invalid operand type: m16&32 is not yet implemented.");

    case Operand::m32$32:
        // Double memory operand
        // TODO ?
        throw ConversionException(virtual_address, "Invalid operand type: m32&32 (or m16&16) is not yet implemented.");

    case Operand::Sreg:
        // Segment register index
        inst.op2_type = OpType::SREG;
        inst.op2_register = Register(ZydisRegisterGetId(IA32inst.operands[1].reg.value));
        break;
    }

    // Third immediate operand
    if (extract_data.has_immediate_operand) {
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "The implementation is wrong, since the previous operands also used an immediate value, leaving no space for the third operand.");
        }

        if (IA32inst.operands[2].type != ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            throw ConversionException(virtual_address, "Wrong third operand type.");
        }

        switch (IA32inst.operands[2].element_type) {
        case ZYDIS_ELEMENT_TYPE_INT:
            // Cast the value properly to limit the number of ones in the final value.
            switch (IA32inst.operands[2].element_size) {
            case 8:
                inst.immediate_value = (uint8_t) IA32inst.operands[2].imm.value.u;
                break;

            case 16:
                inst.immediate_value = (uint16_t) IA32inst.operands[2].imm.value.u;
                break;

            case 32:
                inst.immediate_value = (uint32_t) IA32inst.operands[2].imm.value.u;
                break;

            default:
                throw ConversionException(virtual_address, "Unknown third immediate operand size: %d\n", IA32inst.operands[2].element_size);
            }

        case ZYDIS_ELEMENT_TYPE_UINT:
            inst.immediate_value = IA32inst.operands[2].imm.value.u;
            break;

        default:
            throw ConversionException(virtual_address, "Incompatible third operand type: %d\n", IA32inst.operands[2].element_type);
        }
    }

    inst.read_op1 = extract_data.read_operand_1;
    inst.read_op2 = extract_data.read_operand_2;

    inst.write_ret1_to_op1 = extract_data.write_ret_1_to_op_1;
    inst.write_ret2_to_op2 = extract_data.write_ret_2_to_op_2;

    inst.write_ret1_to_register = extract_data.write_ret_1_register;
    inst.scale_output_override = extract_data.write_ret_1_register_scale;
    inst.register_out = extract_data.write_ret_1_out_register;

    inst.get_flags = extract_data.get_flags;
}
