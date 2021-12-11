
#include <iostream>
#include <cstring>
#include <limits>
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
 */
template<size_t N>
void scan_optional_format(const std::string& str, const char* format, const std::array<std::any, N>& args)
{
    size_t args_index = 0;

    std::from_chars_result status{};
    status.ptr = str.c_str();

    const char* str_end = str.c_str() + str.length();

    int value;

    char format_c;
    while ((format_c = *format++) != '\0'
           && args_index < N
           && status.ptr < str_end) {
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
    if (status.ptr - str_end != -1) {
    	std::string parsed(str, int(status.ptr - str_end));
    	throw IA32::LoadingException("The last string pos isn't at the end of the string:\nStopped at:\t'%s' (%d)\nComplete str:\t'%s' (%d)", parsed.c_str(), int(status.ptr - str.c_str()), str.c_str(), int(str_end - str.c_str()));
    }
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
 * @param register_in_opcode If the opcode contains the register for the first operand.
 * @param first_operand First operand of the instruction
 * @param second_operand Second operand of the instruction
 */
static constexpr bool is_mod_rm_byte_present(bool digit_flag_present, bool register_in_opcode, IA32::Operand first_operand, IA32::Operand second_operand)
{
    if (digit_flag_present) {
        return true;
    }

    if (register_in_opcode) {
        // All instructions supported don't use a Mod r/m byte when they have a register in their opcode
        return false;
    }

    for (auto&& operand : {first_operand, second_operand}) {
        switch (operand) {
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
        try {
            scan_optional_format(line, format, format_values);
        }
        catch (const IA32::LoadingException& e) {
            std::cout << "Error while parsing line " << line_nb << "\n";
            throw;
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

        inst.has_mod_byte = is_mod_rm_byte_present(extension != 0, repeat_for_all_registers, inst.operand_1, inst.operand_2);

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


bool IA32::Mapping::is_opcode_known(ZyanU16 opcode) const
{
    return instructions_extraction_info.contains(opcode);
}


bool IA32::Mapping::has_opcode_reg_extension(ZyanU16 opcode) const
{
    return opcodes_with_reg_extension.contains(opcode);
}


const IA32::Inst& IA32::Mapping::get_extraction_data(ZyanU16 opcode) const
{
    return instructions_extraction_info.at(opcode);
}
