
#include <array>
#include <forward_list>
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
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);

    INFO("Mappings loaded.");

    initialized = true;
}


void find_instructions_differences(const Instruction& generated, const Instruction& expected)
{
    CHECK_EQ(generated.opcode, expected.opcode);

    CHECK_EQ(generated.operand_size_override, expected.operand_size_override);
    CHECK_EQ(generated.operand_byte_size_override, expected.operand_byte_size_override);

    CHECK_EQ(generated.get_flags, expected.get_flags);
    CHECK_EQ(generated.get_CR0, expected.get_CR0);

    CHECK_EQ(generated.op1.type, expected.op1.type);
    CHECK_EQ(generated.op1.reg, expected.op1.reg);
    CHECK_EQ(generated.op1.read, expected.op1.read);

    CHECK_EQ(generated.op2.type, expected.op2.type);
    CHECK_EQ(generated.op2.reg, expected.op2.reg);
    CHECK_EQ(generated.op2.read, expected.op2.read);

    CHECK_EQ(generated.write_ret1_to_op1, expected.write_ret1_to_op1);
    CHECK_EQ(generated.write_ret2_to_op2, expected.write_ret2_to_op2);

    CHECK_EQ(generated.write_ret2_to_register, expected.write_ret2_to_register);
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
 *        <instruction in intel syntax>
 *
 *  - compile with gcc:            gcc -m32 -c <assembly_file>
 *  - then decompile with objdump: objdump -M intel -d <object file>
 *
 *
 * Or using the bash script: ./encode_inst.sh '<instruction in intel syntax>'
 * All of the above is handled properly by the script.
 */


struct TestInfo {
    const char* test_name;
    std::array<uint8_t, 8> data;
    Instruction expected;
};


static const std::array<TestInfo, 10> instructions_test_cases{
    TestInfo{
        "AAA", { /* AAA */ 0x37 }, {
            .opcode = 0,
            .op1 = { OpType::REG, Register::EAX, true },
            .get_flags = true,
            .write_ret1_to_op1 = true,
        },
    }, TestInfo{
        "ADD", { /* ADD eax, 69 */ 0x83, 0xC0, 0x45 }, {
           .opcode = 5,
           .op1 = { OpType::REG, Register::EAX, true },
           .op2 = { .type = OpType::IMM, .read = true },
           .get_flags = true,
           .write_ret1_to_op1 = true,
           .immediate_value = 69
       },
    }, TestInfo{
        "ADD_8bits", { /* ADD AL, 42 */ 0x04, 0x2A }, {
            .opcode = 5,
            .op1 = { OpType::REG, Register::AL, true },
            .op2 = { .type = OpType::IMM, .read = true },
            .operand_byte_size_override = true,
            .get_flags = true,
            .write_ret1_to_op1 = true,
            .immediate_value = 42
        }
    }, TestInfo{
        "ADD_16bits", { /* ADD AX, 0xFF01 */ 0x66, 0x05, 0x01, 0xFF }, {
            .opcode = 5,
            .op1 = { OpType::REG, Register::AX, true },
            .op2 = { .type = OpType::IMM, .read = true },
            .operand_size_override = true,
            .get_flags = true,
            .write_ret1_to_op1 = true,
            .immediate_value = 0xFF01
        },
    }, TestInfo{
        "ADD_r/m8_imm8", { /* ADD BYTE PTR [eax], 42 */ 0x80, 0x00, 0x2A }, {
            .opcode = 5,
            .op1 = { OpType::MEM, Register::EAX, true },
            .op2 = { .type = OpType::IMM, .read = true },
            .operand_byte_size_override = true,
            .get_flags = true,
            .write_ret1_to_op1 = true,
            .reg_present = true,
            .reg = uint8_t(Register::EAX),
            .immediate_value = 42
        },
    }, TestInfo{
        "ADD_r/m_imm", { /* ADD DWORD PTR [eax], 4242 */ 0x81, 0x00, 0x92, 0x10, 0x00, 0x00 }, {
            .opcode = 5,
            .op1 = { OpType::MEM, Register::EAX, true },
            .op2 = { .type = OpType::IMM, .read = true },
            .get_flags = true,
            .write_ret1_to_op1 = true,
            .reg_present = true,
            .reg = uint8_t(Register::EAX),
            .immediate_value = 4242
        },
    }, TestInfo{
        "MOV", { /* MOV eax, 42 */ 0xB8, 0x2A, 0x00, 0x00, 0x00 }, {
            .opcode = 32,
            .op1 = { OpType::REG, Register::EAX, false },
            .op2 = { .type = OpType::IMM, .read = true },
            .write_ret1_to_op1 = true,
            .immediate_value = 42
        }
    }, TestInfo{
        "MOV_moffs", { /* MOV cs:label, eax */ 0x2E, 0xA3, 0x07, 0x00, 0x00, 0x00 }, {
            .opcode = 32,
            .op1 = { .type = OpType::IMM_MEM, .read = false },
            .op2 = { OpType::REG, Register::EAX, true },
            .write_ret1_to_op1 = true,
            .address_value = 0x80000 | 0x07
        }
    }, TestInfo{
        "MOV_r/m_sib", { /* MOV BYTE PTR [eax+ecx*8], 42 */ 0xC6, 0x04, 0xC8, 0x2A }, {
            .opcode = 32,
            .op1 = { .type = OpType::MEM, .read = false },
            .op2 = { .type = OpType::IMM, .read = true },
            .operand_byte_size_override = true,
            .write_ret1_to_op1 = true,
            .reg_present = true,
            .reg = uint8_t(Register::ECX),
            .scale = 0b11,
            .base_present = true,
            .base_reg = uint8_t(Register::EAX),
            .displacement_present = false,
            .immediate_value = 42
        }
    },

    /* TODO : this instruction should cause problems: a jump using a lookup table to know where to jump.
     *  This seems to be the same shape every time, so there is maybe something that can be done to fix this.
     *  There shouldn't be anything to change in the instruction, just only the values pointed to, but how many?
     */
    TestInfo{
        "JMP_r/m_sib", { /* JMP DWORD PTR [eax*4+0x8000042] */ 0xFF, 0x24, 0x85, 0x42, 0x00, 0x00, 0x08 }, {
            .opcode = 196,
            .op1 = { .type = OpType::MEM, .read = true },
            .op2 = { .type = OpType::IMM_MEM, .read = true },
            .reg_present = true,
            .reg = uint8_t(Register::EAX),
            .scale = 0b10,
            .base_present = false,
            .displacement_present = true,
            .address_value = 0x8000000 | 0x42
        }
    },
};


TEST_CASE("x86 Instructions")
{
    init();

    for (const auto& test : instructions_test_cases) {
        SUBCASE(test.test_name) {
            test_instruction_conversion(test.data.data(), test.data.size(), test.expected);
        }
    }
}
