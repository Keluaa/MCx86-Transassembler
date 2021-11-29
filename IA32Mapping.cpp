
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
 *  - '%d' decimal integer conversion (value type: unsigned int*)
 *  - '%x' hexadecimal integer conversion (value type: unsigned int*)
 *  - '%o' binary integer conversion (value type: unsigned int*)
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
            	throw IA32::LoadingException("Wrong format: '%%%c'", *(format - 1));
                
            case 'b': // boolean
                if (*status.ptr == *format) {
                    // The next character in the string is the character after %b -> skip this argument
                    args_index++;
                    continue;
                }
                status = std::from_chars(status.ptr, str_end, value);
                if (status.ec != std::errc()) {
                    // Conversion error
                    std::error_code ec = std::make_error_code(status.ec);
                   throw IA32::LoadingException("Conversion error for %%b: %s", ec.message().c_str());
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
                    std::error_code ec = std::make_error_code(status.ec);
                    throw IA32::LoadingException("Conversion error for %%d: %s", ec.message().c_str());
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
                    std::error_code ec = std::make_error_code(status.ec);
                    throw IA32::LoadingException("Conversion error for %%x: %s", ec.message().c_str());
                }
                *std::any_cast<uint32_t*>(args.at(args_index)) = value;
                break;

            case 'o': // binary number
                if (*status.ptr == *format) {
                    // The next character in the string is the character after %x -> skip this argument
                    args_index++;
                    continue;
                }
                status = std::from_chars(status.ptr, str_end, value, 2);
                if (status.ec != std::errc()) {
                    // Conversion error
                    std::error_code ec = std::make_error_code(status.ec);
                    throw IA32::LoadingException("Conversion error for %%o: %s", ec.message().c_str());
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
                    // Malformed format
                    throw IA32::LoadingException("Malformed format for %%s");
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
            	throw IA32::LoadingException("The string doesn't match the character '%c' at pos %d", format_c, status.ptr - 1 - str.c_str());
            }
        }
    }

    // The last 'status.ptr' value should point to the character before the '\0'
    if (status.ptr - str_end != 0) {
    	std::string parsed(str, int(status.ptr - str_end));
    	throw IA32::LoadingException("The last string pos isn't at the end of the string:\nStopped at:\t'%s' (%d)\nComplete str:\t'%s' (%d)", parsed.c_str(), int(status.ptr - str.c_str()), str.c_str(), int(str_end - str.c_str()));
    }
    
    return 0;
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


static IA32::Operand explicit_register_from_name(const char* name)
{
    switch (chars_to_int(name)) {
    case 0:                       return IA32::Operand::None;

    case chars_to_int("AL"):  return IA32::Operand::AL;
    case chars_to_int("AH"):  return IA32::Operand::AH;
    case chars_to_int("EAX"): return IA32::Operand::EAX;

    case chars_to_int("CL"):  return IA32::Operand::CL;
    case chars_to_int("ECX"): return IA32::Operand::ECX;

    case chars_to_int("DL"):  return IA32::Operand::DL;
    case chars_to_int("EDX"): return IA32::Operand::EDX;

    case chars_to_int("A"):   return IA32::Operand::A;
    case chars_to_int("C"):   return IA32::Operand::C;
    case chars_to_int("D"):   return IA32::Operand::D;
    case chars_to_int("B"):   return IA32::Operand::B;

    default:
    	throw IA32::LoadingException("Invalid register name: '%s'", name);
    }
}


static IA32::Operand operand_descriptor_from_str(const char* desc)
{
    switch (chars_to_int(desc)) {

    case 0:
    case chars_to_int("NONE"):
    case chars_to_int("None"):
    case chars_to_int("none"):
        return IA32::Operand::None;

    // Explicit register operands
    case chars_to_int("AL"):       return IA32::Operand::AL;
    case chars_to_int("AH"):       return IA32::Operand::AH;
    case chars_to_int("AX"):
    case chars_to_int("EAX"):      return IA32::Operand::EAX;   // AX or EAX depending on the operand size

    case chars_to_int("CL"):       return IA32::Operand::CL;
    case chars_to_int("CX"):
    case chars_to_int("ECX"):      return IA32::Operand::ECX;   // CX or ECX depending on the operand size

    case chars_to_int("DL"):       return IA32::Operand::DL;
    case chars_to_int("DX"):
    case chars_to_int("EDX"):      return IA32::Operand::EDX;   // DX or EDX depending on the operand size

    // Scaled register operands
    case chars_to_int("A"):        return IA32::Operand::A;     // AL, AX or EAX depending on the operand size
    case chars_to_int("C"):        return IA32::Operand::C;     // CL, CX or ECX depending on the operand size
    case chars_to_int("D"):        return IA32::Operand::D;     // DL, DX or EDX depending on the operand size
    case chars_to_int("B"):        return IA32::Operand::B;     // BL, BX or EBX depending on the operand size

    // Explicit segment register operands
    case chars_to_int("CS"):        return IA32::Operand::CS;
    case chars_to_int("SS"):        return IA32::Operand::SS;
    case chars_to_int("DS"):        return IA32::Operand::DS;
    case chars_to_int("ES"):        return IA32::Operand::ES;
    case chars_to_int("FS"):        return IA32::Operand::FS;
    case chars_to_int("GS"):        return IA32::Operand::GS;

    // Implicit register operands, encoded into the opcode
    case chars_to_int("reg"):      return IA32::Operand::reg;   // reg16 or reg32 depending on the operand size
    case chars_to_int("reg8"):     return IA32::Operand::reg8;

    // Register or memory operands
    case chars_to_int("r/m"):      return IA32::Operand::rm;    // r/m16 or r/m32 depending on the operand size
    case chars_to_int("r/m8"):     return IA32::Operand::rm8;
    case chars_to_int("r/m16"):    return IA32::Operand::rm16;

    // Register operands
    case chars_to_int("r"):        return IA32::Operand::r;     // r16 or r32 depending on the operand size
    case chars_to_int("r8"):       return IA32::Operand::r8;
    case chars_to_int("r16"):      return IA32::Operand::r16;
    case chars_to_int("r32"):      return IA32::Operand::r32;

    // Memory operands
    case chars_to_int("m"):        return IA32::Operand::m;     // m16 or m32 depending on the operand size
    case chars_to_int("m8"):       return IA32::Operand::m8;

    // Immediate operands
    case chars_to_int("imm"):      return IA32::Operand::imm;      // imm8, imm16 or imm32 depending on the operand size
    case chars_to_int("imm8"):     return IA32::Operand::imm8;
    case chars_to_int("imm16"):    return IA32::Operand::imm16;
    case chars_to_int("imm32"):    return IA32::Operand::imm32;

    // Constant immediate operand
    case chars_to_int("cst"):      return IA32::Operand::cst;

    // Relative address operands
    case chars_to_int("rel"):      return IA32::Operand::rel;      // rel8, rel16 or rel32 depending on the operand size

    // Memory offset operands
    case chars_to_int("moffs"):    return IA32::Operand::moffs;    // moffs8, moffs16 or moffs32 depending on the operand size

    // Far pointer operands
    case chars_to_int("ptr16:32"): return IA32::Operand::ptr16_32; // ptr16_32 or ptr16_16 depending on the operand size

    // Far memory operands
    case chars_to_int("m16:32"):   return IA32::Operand::m16_32;   // m16_32 or m16_16 depending on the operand size

    // Double memory operands
    case chars_to_int("m16&32"):   return IA32::Operand::m16$32;
    case chars_to_int("m32&32"):   return IA32::Operand::m32$32;   // m16_32 or m16_16 depending on the operand size

    // Segment register operands
    case chars_to_int("Sreg"):     return IA32::Operand::Sreg;

    // Control register operands
    case chars_to_int("Creg"):     return IA32::Operand::Creg;

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
        case IA32::Operand::r16:
        case IA32::Operand::r32:
        case IA32::Operand::m:
        case IA32::Operand::m8:
        case IA32::Operand::rm:
        case IA32::Operand::rm8:
        case IA32::Operand::rm16:
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
 * @param rm_value Value of the r/m part of the Mod r/m byte
 */
static constexpr bool is_sib_byte_present(uint8_t rm_value)
{
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
 *  - First result register (string, see explicit_register_from_name)
 */
bool IA32::Mapping::load_instructions_extract_info(std::fstream& mapping_file, const ComputerOpcodesInfo& opcodes_info)
{
    // skip the header row
    mapping_file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    IA32::Inst inst{};

    char line_buffer[512] = "";
    std::string line;

    std::string tmp_equiv_mnemonic, tmp_operand_1, tmp_operand_2, tmp_opt_imm_3, tmp_ret_reg;
    tmp_equiv_mnemonic.reserve(10);
    tmp_operand_1.reserve(10);
    tmp_operand_2.reserve(10);
    tmp_ret_reg.reserve(10);

    uint32_t tmp_opcode;
    uint32_t extension;
    uint32_t tmp_imm_val;

    bool repeat_for_all_registers;
    bool tmp_keep_overrides;
    bool tmp_read_op1, tmp_read_op2, tmp_write_r1_op1, tmp_write_r2_op2;
    bool tmp_write_r2_reg, tmp_ret_reg_scale;

    const std::array format_values{
        std::make_any<uint32_t*>(&tmp_opcode),
        std::make_any<uint32_t*>(&extension),
        std::make_any<bool*>(&repeat_for_all_registers),
        std::make_any<std::string*>(&tmp_equiv_mnemonic),
        std::make_any<bool*>(&tmp_keep_overrides),
        std::make_any<std::string*>(&tmp_operand_1),
        std::make_any<std::string*>(&tmp_operand_2),
        std::make_any<std::string*>(&tmp_opt_imm_3),
        std::make_any<bool*>(&tmp_read_op1),
        std::make_any<bool*>(&tmp_read_op2),
        std::make_any<bool*>(&tmp_write_r1_op1),
        std::make_any<bool*>(&tmp_write_r2_op2),
        std::make_any<bool*>(&tmp_write_r2_reg),
        std::make_any<bool*>(&tmp_ret_reg_scale),
        std::make_any<std::string*>(&tmp_ret_reg),
        std::make_any<uint32_t*>(&tmp_imm_val),
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
        tmp_imm_val = 0;
        repeat_for_all_registers = false;
        tmp_keep_overrides = true;
        tmp_read_op1 = false;
        tmp_read_op2 = false;
        tmp_write_r1_op1 = false;
        tmp_write_r2_op2 = false;
        tmp_write_r2_reg = false;
        tmp_ret_reg_scale = false;
        tmp_operand_1.clear();
        tmp_operand_2.clear();
        tmp_opt_imm_3.clear();
        tmp_ret_reg.clear();

        // Scan the line
        const char format[] = "%x,%d,%b,%s,%b,%s,%s,%s,%b,%b,%b,%b,%b,%b,%s,%o\r";
        if (scan_optional_format(line, format, format_values)) {
            // Not all of the line has been parsed
            throw LoadingException("Invalid characters at line %d (mnemonic: %s)", line_nb + 2, inst.mnemonic);
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
        inst.operand_1 = operand_descriptor_from_str(tmp_operand_1.c_str());
        inst.operand_2 = operand_descriptor_from_str(tmp_operand_2.c_str());
        inst.operand_3_imm = operand_descriptor_from_str(tmp_opt_imm_3.c_str());
        inst.read_operand_1 = tmp_read_op1;
        inst.read_operand_2 = tmp_read_op2;
        inst.write_ret_1_to_op_1 = tmp_write_r1_op1;
        inst.write_ret_2_to_op_2 = tmp_write_r2_op2;
        inst.write_ret_2_register = tmp_write_r2_reg;
        inst.write_ret_register_scale = tmp_ret_reg_scale;
        inst.write_ret_out_register = explicit_register_from_name(tmp_ret_reg.c_str());
        inst.immediate_value = (uint8_t) tmp_imm_val;

        inst.has_mod_byte = is_mod_rm_byte_present(extension != 0, inst.operand_1, inst.operand_2);

        ComputerOpcodesInfo::OpcodeInfo opcode_info = opcodes_info.get_infos(inst.equiv_mnemonic);
        inst.equiv_opcode = opcode_info.opcode;
        inst.get_flags = opcode_info.get_flags;
        inst.get_CR0 = opcode_info.get_control_registers;

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


constexpr Register IA32::Mapping::scale_register(uint8_t index, bool override_8bits, bool override_16bits,
                                                 const uint32_t& virtual_address)
{
    if (override_8bits) {
        switch (index) {
        case 0b000: return Register::AL;
        case 0b001: return Register::CL;
        case 0b010: return Register::DL;
        case 0b011: return Register::BL;
        case 0b100: return Register::AH;
        case 0b101: return Register::CH;
        case 0b110: return Register::DH;
        case 0b111: return Register::BH;
        default: break;
        }
    }
    else if (override_16bits) {
        switch (index) {
        case 0b000: return Register::AX;
        case 0b001: return Register::CX;
        case 0b010: return Register::DX;
        case 0b011: return Register::BX;
        case 0b100: return Register::SP;
        case 0b101: return Register::BP;
        case 0b110: return Register::SI;
        case 0b111: return Register::DI;
        default: break;
        }
    }
    else {
        switch (index) {
        case 0b000: return Register::EAX;
        case 0b001: return Register::ECX;
        case 0b010: return Register::EDX;
        case 0b011: return Register::EBX;
        case 0b100: return Register::ESP;
        case 0b101: return Register::EBP;
        case 0b110: return Register::ESI;
        case 0b111: return Register::EDI;
        default: break;
        }
    }

    throw IA32::ConversionException(virtual_address, "Invalid register index: %d", index);
}


void IA32::Mapping::convert_operand(const ZydisDecodedInstruction& IA32inst, const IA32::Inst& extract_data, Instruction& inst,
                                    uint32_t virtual_address, uint32_t segment_base_address, uint8_t op_index,
                                    const Operand& inst_operand, Instruction::Operand& op,
                                    bool rm_is_register_operand, uint8_t rm_index)
{
    bool override_8bits = inst.operand_byte_size_override;
    bool override_16bits = inst.operand_size_override;

    switch (inst_operand) {
    case Operand::None: break;

    case Operand::AL:  op.type = OpType::REG; op.reg = Register::AL;  break;
    case Operand::AH:  op.type = OpType::REG; op.reg = Register::AH;  break;
    case Operand::EAX: op.type = OpType::REG; op.reg = Register::EAX; break;

    case Operand::CL:  op.type = OpType::REG; op.reg = Register::CL;  break;
    case Operand::ECX: op.type = OpType::REG; op.reg = Register::ECX; break;

    case Operand::DL:  op.type = OpType::REG; op.reg = Register::DL;  break;
    case Operand::EDX: op.type = OpType::REG; op.reg = Register::EDX; break;

    case Operand::A:
        op.type = OpType::REG;
        switch (IA32inst.operand_width) {
        case 8:  op.reg = Register::AL;  break;
        case 16: op.reg = Register::AX;  break;
        case 32: op.reg = Register::EAX; break;
        }
        break;

    case Operand::C:
        op.type = OpType::REG;
        switch (IA32inst.operand_width) {
        case 8:  op.reg = Register::CL;  break;
        case 16: op.reg = Register::CX;  break;
        case 32: op.reg = Register::ECX; break;
        }
        break;

    case Operand::D:
        op.type = OpType::REG;
        switch (IA32inst.operand_width) {
        case 8:  op.reg = Register::DL;  break;
        case 16: op.reg = Register::DX;  break;
        case 32: op.reg = Register::EDX; break;
        }
        break;

    case Operand::B:
        op.type = OpType::REG;
        switch (IA32inst.operand_width) {
        case 8:  op.reg = Register::BL;  break;
        case 16: op.reg = Register::BX;  break;
        case 32: op.reg = Register::EBX; break;
        }
        break;

    case Operand::CS: op.type = OpType::REG; op.reg = Register::CS; break;
    case Operand::SS: op.type = OpType::REG; op.reg = Register::SS; break;
    case Operand::DS: op.type = OpType::REG; op.reg = Register::DS; break;
    case Operand::ES: op.type = OpType::REG; op.reg = Register::ES; break;
    case Operand::FS: op.type = OpType::REG; op.reg = Register::FS; break;
    case Operand::GS: op.type = OpType::REG; op.reg = Register::GS; break;

    case Operand::reg8:
        op.type = OpType::REG;
        // The register index is encoded in the first 3 bits of the opcode
        op.reg = scale_register(inst.opcode & 0b111, true, false, virtual_address);
        break;

    case Operand::reg:
        op.type = OpType::REG;
        // The register index is encoded in the first 3 bits of the opcode
        op.reg = scale_register(inst.opcode & 0b111, override_8bits, override_16bits, virtual_address);
        break;

    case Operand::r8:
        op.type = OpType::REG;
        op.reg = scale_register(ZydisRegisterGetId(IA32inst.operands[op_index].reg.value),
                                true, false, virtual_address);
        break;

    case Operand::r16:
        op.type = OpType::REG;
        op.reg = scale_register(ZydisRegisterGetId(IA32inst.operands[op_index].reg.value),
                                false, true, virtual_address);
        break;

    case Operand::r32:
        op.type = OpType::REG;
        op.reg = scale_register(ZydisRegisterGetId(IA32inst.operands[op_index].reg.value),
                                false, false, virtual_address);
        break;

    case Operand::r:
        op.type = OpType::REG;
        op.reg = scale_register(ZydisRegisterGetId(IA32inst.operands[op_index].reg.value),
                                override_8bits, override_16bits, virtual_address);
        break;

    case Operand::rm8:
        if (rm_is_register_operand) {
            op.type = OpType::REG;
            op.reg = scale_register(rm_index, true, false, virtual_address);
        }
        else {
            // Since the operand size is not encoded into the memory operands, the operand size must match.
            if (!override_8bits || override_16bits) {
                throw ConversionException(virtual_address, "The operand size should be 8 bits.");
            }
            op.type = OpType::MEM;
        }
        break;

    case Operand::rm16:
        if (rm_is_register_operand) {
            op.type = OpType::REG;
            op.reg = scale_register(rm_index, false, true, virtual_address);
        }
        else {
            // Since the operand size is not encoded into the memory operands, the operand size must match.
            if (override_8bits || !override_16bits) {
                throw ConversionException(virtual_address, "The operand size should be 16 bits.");
            }
            op.type = OpType::MEM;
        }
        break;

    case Operand::rm:
        if (rm_is_register_operand) {
            op.type = OpType::REG;
            op.reg = scale_register(rm_index, override_8bits, override_16bits, virtual_address);
        }
        else {
            // Since the operand size is not encoded into the memory operands, the operand size must match.
            if (override_8bits) {
                throw ConversionException(virtual_address, "The operand size should not be 8 bits.");
            }
            op.type = OpType::MEM;
        }
        break;

    case Operand::m8:
        // Since the operand size is not encoded into the memory operands, the operand size must match.
        if (!override_8bits || override_16bits) {
            throw ConversionException(virtual_address, "The operand size should be 8 bits.");
        }
    case Operand::m:
        op.type = OpType::MEM;
        break;

        // For each immediate value, we only keep the bytes we are interested in, without sign-extending the value.
        // If the value needed to be sign-extended, Zydis already did it for us, and we use the new value through the
        // wanted size of the immediate.
    case Operand::imm8:
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "Immediate value already used: %d", inst.immediate_value);
        }
        op.type = OpType::IMM;
        inst.immediate_value = (uint8_t) IA32inst.operands[op_index].imm.value.u;
        break;

    case Operand::imm16:
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "Immediate value already used: %d", inst.immediate_value);
        }
        op.type = OpType::IMM;
        inst.immediate_value = (uint16_t) IA32inst.operands[op_index].imm.value.u;
        break;

    case Operand::imm32:
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "Immediate value already used: %d", inst.immediate_value);
        }
        op.type = OpType::IMM;
        inst.immediate_value = (uint32_t) IA32inst.operands[op_index].imm.value.u;
        break;

    case Operand::imm:
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "Immediate value already used: %d", inst.immediate_value);
        }
        op.type = OpType::IMM;
        // Use decoded result to find the size of the immediate
        switch (IA32inst.operands[op_index].element_size) {
        case 8:
            inst.immediate_value = (uint8_t) IA32inst.operands[op_index].imm.value.u;
            break;

        case 16:
            inst.immediate_value = (uint16_t) IA32inst.operands[op_index].imm.value.u;
            break;

        case 32:
            inst.immediate_value = (uint32_t) IA32inst.operands[op_index].imm.value.u;
            break;

        default:
            throw ConversionException(virtual_address, "Unknown immediate operand size: %d\n", IA32inst.operands[op_index].element_size);
        }
        break;

    case Operand::cst:
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "Immediate value already used: %d", inst.immediate_value);
        }
        op.type = OpType::IMM;
        inst.immediate_value = extract_data.immediate_value;
        break;

        // For memory offsets operands, we compute the actual virtual address here
        // TODO : check if the calculations are not off by one
    case Operand::rel:
        if (inst.address_value != 0) {
            throw ConversionException(virtual_address, "Address value already used: 0x%x", inst.address_value);
        }
        op.type = OpType::IMM_MEM;
        // Signed offset relative to the end of the instruction
        inst.address_value = virtual_address + IA32inst.length + IA32inst.operands[op_index].imm.value.s;
        break;

    case Operand::moffs:
        if (inst.address_value != 0) {
            throw ConversionException(virtual_address, "Address value already used: 0x%x", inst.address_value);
        }
        op.type = OpType::IMM_MEM;
        if (IA32inst.operands[op_index].mem.segment != ZYDIS_REGISTER_CS) {
            // moffs operands are offsets from the base address of the segment provided (through prefixes)
            // We only have the base address of the current code segment
            throw ConversionException(virtual_address, "Cannot deduce the base address of another segment");
        }
        // Unsigned offset relative to the current segment
        inst.address_value = segment_base_address + IA32inst.operands[op_index].mem.disp.value;
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
        // TODO ? (only for BOUND, one of the least used instruction I suppose)
        throw ConversionException(virtual_address, "Invalid operand type: m32&32 (or m16&16) is not yet implemented.");

    case Operand::Sreg:
        // Segment register
        op.type = OpType::REG;
        switch (IA32inst.operands[op_index].reg.value) {
        // For some reason the segment registers of Zydis are mis-ordered in the enum
        case ZYDIS_REGISTER_ES: op.reg = Register::ES; break;
        case ZYDIS_REGISTER_CS: op.reg = Register::CS; break;
        case ZYDIS_REGISTER_SS: op.reg = Register::SS; break;
        case ZYDIS_REGISTER_DS: op.reg = Register::DS; break;
        case ZYDIS_REGISTER_FS: op.reg = Register::FS; break;
        case ZYDIS_REGISTER_GS: op.reg = Register::GS; break;
        default:
            throw ConversionException(virtual_address, "Invalid segment register index: %d",
                                      ZydisRegisterGetId(IA32inst.operands[op_index].reg.value));
        }
        break;

    case Operand::Creg:
        // Control register
        op.type = OpType::REG;
        switch (IA32inst.operands[op_index].reg.value) {
        case ZYDIS_REGISTER_CR0: op.reg = Register::CR0; break;
        case ZYDIS_REGISTER_CR1: op.reg = Register::CR1; break;
        default:
            throw ConversionException(virtual_address, "Invalid control register index: %d",
                                      ZydisRegisterGetId(IA32inst.operands[op_index].reg.value));
        }
        break;

    default:
        throw ConversionException(virtual_address, "Unknown operand type: %x", inst_operand);
    }
}


/**
 * Performs additional changes to some instructions.
 *
 * Some instructions like SETcc or Jcc have a lot of information stored in their opcode, at the expense of having a lot
 * of possible opcodes in the instruction set. Instead we have a single opcode for those, and the variant of the
 * operation is stored in the immediate value.
 */
void IA32::Mapping::post_conversion(const ZydisDecodedInstruction& IA32inst, Instruction& inst)
{
    // TODO : after the merge, use the actual opcode enum here
    switch (inst.opcode) {
    case 40: // ROT
        if (inst.immediate_value != 0) {
            inst.immediate_value &= 0b11111; // Make sure to keep only the useful bits
            inst.immediate_value |= 1 << 5; // Use the immediate value
        }

        switch (IA32inst.mnemonic) {
        case ZYDIS_MNEMONIC_RCL:
            inst.immediate_value |= 1 << 7; // Use the carry
        case ZYDIS_MNEMONIC_ROL:
            inst.immediate_value |= 1 << 6; // Rotate left
            break;

        case ZYDIS_MNEMONIC_RCR:
            inst.immediate_value |= 1 << 7; // Use the carry
        case ZYDIS_MNEMONIC_ROR:
            inst.immediate_value |= 0 << 6; // Rotate right
            break;

        default: break; // This case will never happen just trust me
        }
        break;

    case 42: // SHFT
        if (inst.immediate_value != 0) {
            inst.immediate_value &= 0b11111; // Make sure to keep only the useful bits
            inst.immediate_value |= 1 << 5; // Use the immediate value
        }

        switch (IA32inst.mnemonic) {
        case ZYDIS_MNEMONIC_SALC:
            inst.immediate_value |= 1 << 7; // Signed operation
        case ZYDIS_MNEMONIC_SHL:
            inst.immediate_value |= 1 << 6; // Rotate left
            break;

        case ZYDIS_MNEMONIC_SAR:
            inst.immediate_value |= 1 << 7; // Signed operation
        case ZYDIS_MNEMONIC_SHR:
            inst.immediate_value |= 0 << 6; // Rotate right
            break;

        default: break; // This case will never happen just trust me
        }
        break;

    case 44: // SETcc
        // All opcodes are merged into one, and the condition is encoded in the immediate
        switch (IA32inst.mnemonic) {
        case ZYDIS_MNEMONIC_SETNBE: // Above | Not below or equal
            inst.immediate_value = 0b0000; break;
        case ZYDIS_MNEMONIC_SETNB:  // Above or equal | Not below | Not carry
            inst.immediate_value = 0b0001; break;
        case ZYDIS_MNEMONIC_SETB:   // Below | Carry | Not above or equal
            inst.immediate_value = 0b0010; break;
        case ZYDIS_MNEMONIC_SETBE:  // Below or equal | Not above
            inst.immediate_value = 0b0011; break;
        case ZYDIS_MNEMONIC_SETZ:   // Equal | Zero
            inst.immediate_value = 0b0100; break;
        case ZYDIS_MNEMONIC_SETNLE: // Greater | Not less or equal
            inst.immediate_value = 0b0101; break;
        case ZYDIS_MNEMONIC_SETNL:  // Greater or Equal | Not less
            inst.immediate_value = 0b0110; break;
        case ZYDIS_MNEMONIC_SETL:   // Less | Not greater or equal
            inst.immediate_value = 0b0111; break;
        case ZYDIS_MNEMONIC_SETLE:  // Less or equal | Not greater
            inst.immediate_value = 0b1000; break;
        case ZYDIS_MNEMONIC_SETNZ:  // Not equal | Not zero
            inst.immediate_value = 0b1001; break;
        case ZYDIS_MNEMONIC_SETNO:  // Not overflow
            inst.immediate_value = 0b1010; break;
        case ZYDIS_MNEMONIC_SETNP:  // Not parity | Parity odd
            inst.immediate_value = 0b1011; break;
        case ZYDIS_MNEMONIC_SETNS:  // Not sign
            inst.immediate_value = 0b1100; break;
        case ZYDIS_MNEMONIC_SETO:   // Overflow
            inst.immediate_value = 0b1101; break;
        case ZYDIS_MNEMONIC_SETP:   // Parity | Parity even
            inst.immediate_value = 0b1110; break;
        case ZYDIS_MNEMONIC_SETS:   // Sign
            inst.immediate_value = 0b1111; break;

        default: break; // This case will never happen just trust me
        }
        break;

    case 45: // SHD (SHLD and SHRD)
        if (inst.immediate_value != 0) {
            inst.immediate_value &= 0b11111; // Make sure to keep only the useful bits
        }

        switch (IA32inst.mnemonic) {
        case ZYDIS_MNEMONIC_SHLD:
            inst.immediate_value |= 1 << 5; // Rotate left
            break;

        case ZYDIS_MNEMONIC_SHRD:
            inst.immediate_value |= 0 << 5; // Rotate right
            break;

        default: break; // This case will never happen just trust me
        }
        break;

    case 3 | (1 << 7) | (1 << 6): // Jcc
        // All opcodes are merged into one, and the condition is encoded in the immediate
        switch (IA32inst.mnemonic) {
        case ZYDIS_MNEMONIC_JNBE: // Above | Not below or equal
            inst.immediate_value = 0b0000; break;
        case ZYDIS_MNEMONIC_JNB:  // Above or equal | Not below | Not carry
            inst.immediate_value = 0b0001; break;
        case ZYDIS_MNEMONIC_JB:   // Below | Carry | Not above or equal
            inst.immediate_value = 0b0010; break;
        case ZYDIS_MNEMONIC_JBE:  // Below or equal | Not above
            inst.immediate_value = 0b0011; break;
        case ZYDIS_MNEMONIC_JZ:   // Equal | Zero
            inst.immediate_value = 0b0100; break;
        case ZYDIS_MNEMONIC_JNLE: // Greater | Not less or equal
            inst.immediate_value = 0b0101; break;
        case ZYDIS_MNEMONIC_JNL:  // Greater or Equal | Not less
            inst.immediate_value = 0b0110; break;
        case ZYDIS_MNEMONIC_JL:   // Less | Not greater or equal
            inst.immediate_value = 0b0111; break;
        case ZYDIS_MNEMONIC_JLE:  // Less or equal | Not greater
            inst.immediate_value = 0b1000; break;
        case ZYDIS_MNEMONIC_JNZ:  // Not equal | Not zero
            inst.immediate_value = 0b1001; break;
        case ZYDIS_MNEMONIC_JNO:  // Not overflow
            inst.immediate_value = 0b1010; break;
        case ZYDIS_MNEMONIC_JNP:  // Not parity | Parity odd
            inst.immediate_value = 0b1011; break;
        case ZYDIS_MNEMONIC_JNS:  // Not sign
            inst.immediate_value = 0b1100; break;
        case ZYDIS_MNEMONIC_JO:   // Overflow
            inst.immediate_value = 0b1101; break;
        case ZYDIS_MNEMONIC_JP:   // Parity | Parity even
            inst.immediate_value = 0b1110; break;
        case ZYDIS_MNEMONIC_JS:   // Sign
            inst.immediate_value = 0b1111; break;
        case ZYDIS_MNEMONIC_JCXZ: // CX register is zero
            inst.immediate_value = 0b10000; break;
        case ZYDIS_MNEMONIC_JECXZ: // ECX register is zero
            inst.immediate_value = 0b10001; break;

        default: break; // This case will never happen just trust me
        }
        break;

    default:
        break;
    }
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
        inst.operand_size_override = IA32inst.operand_width == 16; // 16-bits override
        inst.operand_byte_size_override = IA32inst.operand_width == 8; // 8-bits override
    }

    if (IA32inst.address_width != 32) {
        throw ConversionException(virtual_address, "Address sizes different from 32 bits are not supported. Given size: %d bits", IA32inst.address_width);
    }
    if (IA32inst.stack_width != 32) {
        throw ConversionException(virtual_address, "Stack sizes different from 32 bits are not supported. Given size: %d bits", IA32inst.stack_width);
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
        else if (IA32inst.raw.modrm.mod == 0b00 && IA32inst.raw.modrm.rm == 0b101) {
            // Mod r/m byte, alone with no register. There is only a displacement
            inst.displacement_present = true;

            // Extract the displacement value
            inst.address_value = IA32inst.raw.disp.value;
        }
        else {
            // The Mod r/m byte describes a memory operand
            if (is_sib_byte_present(IA32inst.raw.modrm.rm)) {
                inst.reg_present = true;
                inst.reg = IA32inst.raw.sib.index;
                inst.scale = IA32inst.raw.sib.scale;

                if (IA32inst.raw.sib.base == 0b101) {
                    switch (IA32inst.raw.modrm.mod) {
                    case 0b00:
                        // No base, with 32 bit displacement
                        inst.base_present = false;
                        inst.displacement_present = true;
                        inst.address_value = IA32inst.raw.disp.value;
                        break;

                    case 0b01:
                        // With EBP base, with 8 bit displacement
                        inst.base_present = true;
                        inst.base_reg = uint8_t(Register::EBP);
                        inst.address_value = int32_t(int8_t(uint8_t(IA32inst.raw.disp.value)));
                        break;

                    case 0b10:
                        // With EBP base, with 32 bit displacement
                        inst.base_present = true;
                        inst.base_reg = uint8_t(Register::EBP);
                        inst.displacement_present = true;
                        inst.address_value = IA32inst.raw.disp.value;
                        break;
                    }
                }
                else {
                    // Normal base specification
                    inst.base_present = true;
                    inst.base_reg = IA32inst.raw.sib.base;
                }
            }
            else {
                // Mod r/m byte alone
                inst.reg_present = true;
                inst.reg = IA32inst.raw.modrm.rm;
            }

            if (!inst.displacement_present) {
                // Displacement (if it has not been already specified by the SIB byte)
                switch (IA32inst.raw.modrm.mod) {
                case 0b00:
                    inst.displacement_present = false;
                    break;

                case 0b01:
                    inst.displacement_present = true;
                    // 8 bits displacement
                    inst.address_value = int32_t(int8_t(uint8_t(IA32inst.raw.disp.value)));
                    break;

                case 0b10:
                    inst.displacement_present = true;
                    // 32 bits displacement
                    inst.address_value = IA32inst.raw.disp.value;
                    break;
                }
            }
        }
    }

    if (extract_data.has_mod_byte != bool(IA32inst.attributes & ZYDIS_ATTRIB_HAS_MODRM)) {
        // TODO : remove if unnecessary
        throw ConversionException(virtual_address, "Invalid implementation, extraction info is different from the one of the decompiler.");
    }

    // First operand
    convert_operand(IA32inst, extract_data, inst, virtual_address, segment_base_address, 0,
                    extract_data.operand_1, inst.op1, rm_is_register_operand, register_index);

    // Second operand
    convert_operand(IA32inst, extract_data, inst, virtual_address, segment_base_address, 1,
                    extract_data.operand_2, inst.op2, rm_is_register_operand, register_index);

    // Third immediate operand
    if (extract_data.operand_3_imm != Operand::None) {
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "Immediate value already used: %d", inst.immediate_value);
        }

        if (IA32inst.operands[2].type != ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            throw ConversionException(virtual_address, "Wrong third immediate operand type.");
        }

        switch (extract_data.operand_3_imm) {
        case Operand::None: break;

        case Operand::imm8:
            inst.immediate_value = (uint8_t) IA32inst.operands[2].imm.value.u;
            break;

        case Operand::imm16:
            inst.immediate_value = (uint16_t) IA32inst.operands[2].imm.value.u;
            break;

        case Operand::imm32:
            inst.immediate_value = (uint32_t) IA32inst.operands[2].imm.value.u;
            break;

        case Operand::imm:
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
            break;

        default:
            throw ConversionException(virtual_address, "Invalid third operand type: %d\n", extract_data.operand_3_imm);
        }
    }

    inst.op1.read = extract_data.read_operand_1;
    inst.op2.read = extract_data.read_operand_2;

    inst.write_ret1_to_op1 = extract_data.write_ret_1_to_op_1;
    inst.write_ret2_to_op2 = extract_data.write_ret_2_to_op_2;

    inst.write_ret2_to_register = extract_data.write_ret_2_register;
    inst.scale_output_override = extract_data.write_ret_register_scale;

    if (inst.displacement_present) {
        // Make the displacement (if any) an IMM_MEM operand
        if (inst.op1.type == OpType::IMM_MEM || inst.op2.type == OpType::IMM_MEM) {
            // There is already one IMM_MEM operand, everything is fine
        }
        else if (!inst.is_op1_none() && !inst.is_op2_none()) {
            // No available operand
            throw ConversionException(virtual_address, "Cannot make the displacement an operand, both are already taken.");
        }
        else {
            Instruction::Operand& op = inst.is_op1_none() ? inst.op1 : inst.op2;
            op.type = OpType::IMM_MEM;
            op.read = true;
        }
    }

    // Register operand to register index
    switch (extract_data.write_ret_out_register) {
    case Operand::None: break;

    case Operand::AL:  inst.register_out = Register::AL;  break;
    case Operand::AH:  inst.register_out = Register::AX;  break;
    case Operand::EAX: inst.register_out = Register::EAX; break;

    case Operand::CL:  inst.register_out = Register::CL;  break;
    case Operand::ECX: inst.register_out = Register::ECX; break;

    case Operand::DL:  inst.register_out = Register::DL;  break;
    case Operand::EDX: inst.register_out = Register::EDX; break;

    case Operand::A:
        inst.register_out = scale_register(0, inst.operand_size_override, inst.operand_byte_size_override,
                                           virtual_address);
        break;

    case Operand::C:
        inst.register_out = scale_register(1, inst.operand_size_override, inst.operand_byte_size_override,
                                           virtual_address);
        break;

    case Operand::D:
        inst.register_out = scale_register(2, inst.operand_size_override, inst.operand_byte_size_override,
                                           virtual_address);
        break;

    case Operand::B:
        inst.register_out = scale_register(3, inst.operand_size_override, inst.operand_byte_size_override,
                                           virtual_address);
        break;

    default:
        throw ConversionException(virtual_address, "The custom output register must be a register operand.");
    }

    inst.get_flags = extract_data.get_flags;
    inst.get_CR0 = extract_data.get_CR0;

    post_conversion(IA32inst, inst);
}
