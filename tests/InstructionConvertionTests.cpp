
#include <Zydis/Zydis.h>

#include "../IA32Mapping.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"


ZydisDecoder decoder;
IA32Mapping mapping;


void init()
{
    static bool initialized = false;

    if (initialized) {
        return;
    }

    const std::string MAPPING_FILE_PATH = "../IA32_instructions_mapping.csv";

    std::fstream mapping_file_stream;
    mapping_file_stream.open(MAPPING_FILE_PATH, std::ios::in);
    if (mapping_file_stream.bad()) {
        FAIL("Could not open the mapping file.");
    }
    else {
        mapping.load_instruction_mapping(mapping_file_stream);
    }

    // x86 with 32-bit addressing
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);

    initialized = true;
}


void find_instructions_differences(const Instruction& generated, const Instruction& expected)
{
    CHECK_EQ(generated.opcode, expected.opcode);

    CHECK_EQ(generated.address_size_override, expected.address_size_override);
    CHECK_EQ(generated.operand_size_override, expected.operand_size_override);
    CHECK_EQ(generated.address_byte_size_override, expected.address_byte_size_override);
    CHECK_EQ(generated.operand_byte_size_override, expected.operand_byte_size_override);

    CHECK_EQ(generated.get_flags, expected.get_flags);

    CHECK_EQ(generated.op1_type, expected.op1_type);
    CHECK_EQ(generated.op2_type, expected.op2_type);

    CHECK_EQ(generated.op1_register, expected.op1_register);
    CHECK_EQ(generated.op2_register, expected.op2_register);

    CHECK_EQ(generated.read_op1, expected.read_op1);
    CHECK_EQ(generated.read_op2, expected.read_op2);

    CHECK_EQ(generated.write_ret1_to_op1, expected.write_ret1_to_op1);
    CHECK_EQ(generated.write_ret2_to_op2, expected.write_ret2_to_op2);

    CHECK_EQ(generated.write_ret1_to_register, expected.write_ret1_to_register);
    CHECK_EQ(generated.scale_output_override, expected.scale_output_override);
    CHECK_EQ(generated.register_out, expected.register_out);

    CHECK_EQ(generated.compute_address, expected.compute_address);

    CHECK_EQ(generated.raw_address_specifier, expected.raw_address_specifier);

    CHECK_EQ(generated.mod_rm_sib.mod, expected.mod_rm_sib.mod);
    CHECK_EQ(generated.mod_rm_sib.reg, expected.mod_rm_sib.reg);
    CHECK_EQ(generated.mod_rm_sib.rm, expected.mod_rm_sib.rm);

    CHECK_EQ(generated.mod_rm_sib.scale, expected.mod_rm_sib.scale);
    CHECK_EQ(generated.mod_rm_sib.index, expected.mod_rm_sib.index);
    CHECK_EQ(generated.mod_rm_sib.base, expected.mod_rm_sib.base);

    CHECK_EQ(generated.address_value, expected.address_value);
    CHECK_EQ(generated.immediate_value, expected.immediate_value);
}


/*
 * How to encode instructions easily:
 *  - c++ code:
 *    void test()
 *    {
 *        __asm__ volatile("<instruction asm here>\n");
 *    }
 *
 *  - compile with Compiler Explorer using gcc (options: -m32)
 *  - set the 'Compile to binary' output option
 *  - the encoded instruction data will be right above its line
 */


TEST_CASE("ADD")
{
    init();

    const uint8_t data[] = {
            //0xB8, 0x2A, 0x00, 0x00, 0x00, // movl $42, %eax
            0x83, 0xC0, 0x45              // addl $69, %eax
    };

    ZydisDecodedInstruction IA32_inst;
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data, sizeof(data), &IA32_inst)));

    Instruction inst{};
    REQUIRE(mapping.extract_instruction(IA32_inst, inst));

    Instruction expected{
        .opcode = 5, // I think?
        .get_flags = true,
        .op1_type = OpType::REG,
        .op2_type = OpType::IMM,
        .op1_register = 0, // EAX
        .read_op1 = true,
        .read_op2 = true,
        .write_ret1_to_op1 = true,
        .immediate_value = 69
    };

    if (inst != expected) {
        find_instructions_differences(inst, expected);
    }

    // For the first test we check most fields

    /*
    CHECK_EQ(inst.address_size_override, 0);
    CHECK_EQ(inst.operand_size_override, 0);
    CHECK_EQ(inst.address_byte_size_override, 0);
    CHECK_EQ(inst.operand_byte_size_override, 0);

    CHECK_EQ(inst.get_flags, 1);

    CHECK_EQ(inst.op1_type, OpType::REG);
    CHECK_EQ(inst.op2_type, OpType::IMM);

    CHECK_EQ(inst.op1_register, 0); // EAX
    CHECK_EQ(inst.op2_register, 0); // (no register, but EAX anyway)

    CHECK_EQ(inst.read_op1, 1);
    CHECK_EQ(inst.read_op2, 1);

    CHECK_EQ(inst.write_ret1_to_op1, 1);
    CHECK_EQ(inst.write_ret2_to_op2, 0);

    CHECK_EQ(inst.write_ret1_to_register, 0);
    CHECK_EQ(inst.scale_output_override, 0);
    CHECK_EQ(inst.register_out, 0);

    CHECK_EQ(inst.compute_address, 0);

    CHECK_EQ(inst.raw_address_specifier, 0); // no Mod r/m or SIB

    CHECK_EQ(inst.address_value, 0);
    CHECK_EQ(inst.immediate_value, 69);
    */
}
