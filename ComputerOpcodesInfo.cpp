
#include <cstdarg>
#include <stdexcept>
#include <sstream>
#include <charconv>

#include "ComputerOpcodesInfo.h"


/**
 * Alternative to sscanf.
 *
 * This exists only because streams don't support formatted input, and sscanf doesn't support booleans.
 * Supports only %d for decimals, %x for hexadecimals and %b for booleans.
 * Characters outside of the number formats are matched with the characters in the string.
 * Returns true if the format is invalid, if the string doesn't match the format, or if a conversion was unsuccessful.
 */
bool scan_format(const char* format, const char* str, size_t str_length, int format_count...)
{
    va_list args;
    va_start(args, format_count);
    size_t args_index = 0;

    std::from_chars_result status{};
    status.ptr = str;

    const char* str_end = str + str_length;

    int value;

    char format_c;
    while ((format_c = *format++) != '\0'
           && args_index < format_count
           && status.ptr != str_end) {
        if (format_c == '%') {
            switch(*format++) {
            case '\0':
            default:
                // Wrong format
                return true;

            case 'b':
                // boolean
                status = std::from_chars(status.ptr, str_end, value);
                if (status.ec != std::errc()) {
                    // Parsing error
                    return true;
                }
                *va_arg(args, bool*) = (bool) value;
                break;

            case 'd':
                // decimal number
                status = std::from_chars(status.ptr, str_end, value);
                if (status.ec != std::errc()) {
                    // Parsing error
                    return true;
                }
                *va_arg(args, int*) = value;
                break;

            case 'x':
                // hexadecimal number
                status = std::from_chars(status.ptr, str_end, value, 16);
                if (status.ec != std::errc()) {
                    // Parsing error
                    return true;
                }
                *va_arg(args, int*) = value;
                break;
            }
            args_index++;
        }
        else {
            // Try to match the character
            if (*status.ptr++ != format_c) {
                return true;
            }
        }
    }

    va_end(args);

    return format_c != '\0' || args_index != format_count;
}


bool ComputerOpcodesInfo::load_map(std::fstream& opcodes_file)
{
    // skip the header row
    opcodes_file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    const uint8_t not_arithmetic_flag = 1 << 7;
    const uint8_t state_machine_flag = 0b11 << 5;
    const uint8_t jump_flag = 1 << 6;
    const uint8_t string_flag = 1 << 5;

    char mnemonic[8];
    char line[51];
    unsigned int opcode;
    bool is_arithmetic;
    bool is_string;
    bool is_jump;
    bool is_state_machine;
    bool get_flags;
    bool get_control_registers;

    while (opcodes_file.good()) {
        opcodes_file.get(mnemonic, 7, ',');
        opcodes_file.ignore(1); // skip the comma

        if (opcodes_file.eof()) {
            break;
        }

        opcodes_file.getline(line, 50);

        if (scan_format("%d,%b,%b,%b,%b,%b,%b", line, 50, 7,
                        &opcode,
                        &is_arithmetic, &is_string, &is_jump, &is_state_machine,
                        &get_flags, &get_control_registers)) {
            return true;
        }

        if (!is_arithmetic) {
            opcode |= not_arithmetic_flag;
        }
        if (is_state_machine) {
            opcode |= state_machine_flag;
        }
        else if (is_jump) {
            opcode |= jump_flag;
        }
        else if (is_string) {
            opcode |= string_flag;
        }

        opcodes_map.insert(std::pair<std::string, OpcodeInfo>(mnemonic, {(uint8_t) opcode, get_flags, get_control_registers}));
    }

    return opcodes_file.fail();
}


uint8_t ComputerOpcodesInfo::get_opcode(const std::string& mnemonic) const
{
    if (!opcodes_map.contains(mnemonic)) {
        std::ostringstream oss;
        oss << "Unknown mnemonic: '" << mnemonic << "'";
        throw std::out_of_range(oss.str());
    }
    return opcodes_map.at(mnemonic).opcode;
}


const ComputerOpcodesInfo::OpcodeInfo& ComputerOpcodesInfo::get_infos(const std::string& mnemonic) const
{
    if (!opcodes_map.contains(mnemonic)) {
        std::ostringstream oss;
        oss << "Unknown mnemonic: '" << mnemonic << "'";
        throw std::out_of_range(oss.str());
    }
    return opcodes_map.at(mnemonic);
}
