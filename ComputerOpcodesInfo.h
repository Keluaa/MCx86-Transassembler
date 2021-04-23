
#ifndef COMPUTERTRANSASSEMBLER_COMPUTEROPCODESINFO_H
#define COMPUTERTRANSASSEMBLER_COMPUTEROPCODESINFO_H


#include <unordered_map>
#include <string>
#include <fstream>


class ComputerOpcodesInfo
{
public:

    struct OpcodeInfo
    {
        uint8_t opcode;
        bool get_flags;
        bool get_control_registers;
    };

    bool load_map(std::fstream& opcodes_file);

    uint8_t get_opcode(const std::string& mnemonic) const;

    const OpcodeInfo& get_infos(const std::string& mnemonic) const;

private:
    std::unordered_map<std::string, OpcodeInfo> opcodes_map;
};


#endif //COMPUTERTRANSASSEMBLER_COMPUTEROPCODESINFO_H
