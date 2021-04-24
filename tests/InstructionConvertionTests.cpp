
#include "../IA32Mapping.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"


static ZydisDecoder decoder;
static ComputerOpcodesInfo opcodes_info;
static IA32::Mapping mapping;


void init()
{
    static bool initialized = false;

    if (initialized) {
        return;
    }

    const std::string MAPPING_FILE_PATH = "./IA32_instructions_mapping.csv";
    const std::string opcodes_mapping_file_name = "./computer_instructions.csv";

    std::fstream opcodes_file;
    opcodes_file.open(opcodes_mapping_file_name, std::ios::in);
    if (!opcodes_file.is_open()) {
        FAIL("Could not open the opcodes mapping file.");
    }
    else if (!opcodes_info.load_map(opcodes_file)) {
        FAIL("Error when parsing the opcodes mapping file.");
    }
    opcodes_file.close();

    std::fstream mapping_file_stream;
    mapping_file_stream.open(MAPPING_FILE_PATH, std::ios::in);
    if (!mapping_file_stream.is_open()) {
        FAIL("Could not open the mapping file.");
    }
    else {
        REQUIRE_NOTHROW(mapping.load_instructions_extract_info(mapping_file_stream, opcodes_info));
    }
    mapping_file_stream.close();

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

    CHECK_EQ(generated.reg_present, expected.reg_present);
    CHECK_EQ(generated.reg, expected.reg);
    CHECK_EQ(generated.scale, expected.scale);
    CHECK_EQ(generated.base_present, expected.base_present);
    CHECK_EQ(generated.base_reg, expected.base_reg);
    CHECK_EQ(generated.displacement_present, expected.displacement_present);

    CHECK_EQ(generated.address_value, expected.address_value);
    CHECK_EQ(generated.immediate_value, expected.immediate_value);
}


void test_instruction_conversion(const uint8_t* encoded_IA32_inst, size_t encoded_size, const Instruction& expected_result)
{
    ZydisDecodedInstruction IA32_inst;
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, encoded_IA32_inst, encoded_size, &IA32_inst)));

    Instruction inst{};

    REQUIRE_NOTHROW(mapping.convert_instruction(IA32_inst, inst, 0x80000, 0x80000));

    if (inst != expected_result) {
        find_instructions_differences(inst, expected_result);
    }
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
 *
 * Locally one can use gcc and objdump for the same result:
 *  - assembly code:
 *        .text
 *    test:
 *        <instruction in AT&T syntax>
 *
 *  - compile with gcc:          gcc -m32 -c <assembly_file>
 *  - then decompile with objdump: objdump -d <object file>
 *
 * Or with intel syntax:
 *  - assembly code:
 *        .text
 *    test:
 *        .intel_syntax noprefix
 *        <instruction in AT&T syntax>
 *
 *  - compile with gcc:            gcc -m32 -c <assembly_file>
 *  - then decompile with objdump: objdump -M intel -d <object file>
 */


TEST_CASE("AAA")
{
    init();

    const uint8_t data[] = {
            /* aaa */ 0x37
    };

    Instruction expected{
        .opcode = opcodes_info.get_opcode("AAA"),
        .get_flags = true,
        .op1_type = OpType::REG,
        .op1_register = Register::EAX,
        .read_op1 = true,
        .write_ret1_to_op1 = true,
    };

    test_instruction_conversion(data, sizeof(data), expected);
}


TEST_CASE("ADD")
{
    init();

    const uint8_t data[] = {
            /* add eax, 69 */ 0x83, 0xC0, 0x45
    };

    Instruction expected{
        .opcode = opcodes_info.get_opcode("ADD"),
        .get_flags = true,
        .op1_type = OpType::REG,
        .op2_type = OpType::IMM,
        .op1_register = Register::EAX,
        .read_op1 = true,
        .read_op2 = true,
        .write_ret1_to_op1 = true,
        .immediate_value = 69
    };

    test_instruction_conversion(data, sizeof(data), expected);
}


TEST_CASE("MOV")
{
    init();

    const uint8_t data[] = {
            /* mov eax, 42 */ 0xB8, 0x2A, 0x00, 0x00, 0x00,
    };

    Instruction res{
        .opcode = opcodes_info.get_opcode("MOV"),
        .op1_type = OpType::REG,
        .op2_type = OpType::IMM,
        .op1_register = Register::EAX,
        .read_op2 = true,
        .write_ret1_to_op1 = true,
        .immediate_value = 42
    };

    test_instruction_conversion(data, sizeof(data), res);
}
