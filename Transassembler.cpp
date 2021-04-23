
#include <cstdio>
#include <cstring>

#include "Transassembler.h"


Transassembler::Transassembler(const uint8_t* data, const size_t size, const uint64_t addr)
    : data(data), size(size), segment_address(addr), decoder()
{
    // x86 with 32-bit addressing
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
}


void Transassembler::process_jumps()
{
    // Maps the instruction targets to their jumping instructions.
    std::unordered_multimap<ZyanUSize, uint32_t> unprocessed_jump_targets;

    ZyanU64 runtime_address = segment_address;
    ZyanUSize offset = 0;
    uint32_t current_inst = 0;

    ZydisDecodedInstruction inst;
    ZyanUSize jump_target;

    // Parse through all instructions
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, size - offset, &inst))) {
        if (is_instruction_a_jump(inst)) {
            jump_target = get_jump_address(inst, runtime_address);
            if (jump_target != 0) {
                if (instructions_numbers.contains(jump_target)) {
                    processed_jumping_instructions[current_inst] = instructions_numbers[jump_target];
                }
                else {
                    unprocessed_jump_targets.insert(std::pair<ZyanUSize, uint32_t>(jump_target, current_inst));
                }
            }
        }
        if (unprocessed_jump_targets.contains(runtime_address)) {
            auto unprocessed_jumps = unprocessed_jump_targets.equal_range(runtime_address);
            for (auto it = unprocessed_jumps.first; it != unprocessed_jumps.second; it++) {
                processed_jumping_instructions[it->second] = current_inst;
            }
            unprocessed_jump_targets.erase(unprocessed_jumps.first, unprocessed_jumps.second);
        }

        instructions_numbers[runtime_address] = current_inst;

        offset += inst.length;
        runtime_address += inst.length;
        current_inst++;
    }

    if (!unprocessed_jump_targets.empty()) {
        printf("\nWARNING: There is %ld unprocessed jumping instructions.\n", unprocessed_jump_targets.size());
        for (auto&& [jump_addr, inst_number] : unprocessed_jump_targets) {
            printf("%03d  ->  %lx\n", inst_number, jump_addr);
        }
    }
}


void Transassembler::print_disassembly(const ZydisFormatter& formatter) const
{
    ZyanU64 runtime_address = segment_address;
    ZyanUSize offset = 0;
    ZydisDecodedInstruction inst;
    uint32_t current_inst = 0;

    // TODO : handle better decoding errors
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, size - offset, &inst))) {
        // Print current inst number and address
        printf("%03d  %04lx  ", current_inst, runtime_address);

        // Print where does this instruction jumps to
        if (processed_jumping_instructions.contains(current_inst)) {
            printf("%03d  ", processed_jumping_instructions.at(current_inst));
        }
        else {
            printf("     ");
        }

        // Print the decoded instruction
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &inst, buffer, sizeof(buffer), runtime_address);
        puts(buffer);

        offset += inst.length;
        runtime_address += inst.length;
        current_inst++;
    }
}


constexpr bool Transassembler::is_instruction_a_jump(const ZydisDecodedInstruction& inst) {
    switch (inst.mnemonic) {
    case ZYDIS_MNEMONIC_CALL:
    //case ZYDIS_MNEMONIC_INT:  // not a jump we want to process
    //case ZYDIS_MNEMONIC_IRET: // EIP is popped from the stack
    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
    case ZYDIS_MNEMONIC_RET:
    case ZYDIS_MNEMONIC_JMP:

    // all variants of Jcc...
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JKNZD:  // not in 80386
    case ZYDIS_MNEMONIC_JKZD:   // not in 80386
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JRCXZ:  // not in 80386
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JZ:
        return true;

    default:
        assert(!does_instruction_branches(inst)); // if this fails then there is an instruction missing above
        return false; // no jumps for this instruction
    }
}


constexpr ZyanUSize Transassembler::get_jump_address(const ZydisDecodedInstruction& inst, const ZyanUSize inst_address)
{
    ZyanUSize abs_addr = 0;

    switch (inst.mnemonic) {
    case ZYDIS_MNEMONIC_CALL:
    case ZYDIS_MNEMONIC_JMP:
    {
        const ZydisDecodedOperand& op = inst.operands[0];

        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            // Relative offset
            if (!op.imm.is_relative) {
                assert(0); // Should be relative
            }

            assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &op, inst_address, &abs_addr)));
        }
        else {
            // Address in the Mod r/m. If it uses an address from a register, then we have a problem.
            assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &op, inst_address, &abs_addr)));
        }
        break;
    }

    case ZYDIS_MNEMONIC_INT:  // not a jump we want to process
    case ZYDIS_MNEMONIC_IRET: // EIP is popped from the stack
        break;

    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
        assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, inst.operands + 0, inst_address, &abs_addr)));
        break;

    case ZYDIS_MNEMONIC_RET:
        if (inst.operand_count == 1) {
            // Relative offset from the immediate
            assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, inst.operands + 0, inst_address, &abs_addr)));
        }
        else {
            // EIP is popped from the stack, nothing to do
        }
        break;

    // all variants of Jcc...
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JKNZD:  // not in 80386
    case ZYDIS_MNEMONIC_JKZD:   // not in 80386
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JRCXZ:  // not in 80386
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JZ:
        // All variants use a relative offset
        assert(ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, inst.operands + 0, inst_address, &abs_addr)));
        break;

    default:
        break;
    }

    return abs_addr;
}


constexpr bool Transassembler::does_instruction_branches(const ZydisDecodedInstruction& inst) {
    return inst.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE;
}


void Transassembler::convert_instructions(const IA32::Mapping& mapping)
{
    size_t i = 0;

    ZydisDecodedInstruction IA32_inst;
    ZyanU64 runtime_address = segment_address;
    ZyanUSize offset = 0;
    uint32_t current_inst = 0;

    Instruction* inst;
    while (i < INST_BUFFER_SIZE) {
        inst = inst_buffer + i;
        i++;

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, size - offset, &IA32_inst))) {
            // TODO : problem
            break;
        }

        mapping.convert_instruction(IA32_inst, *inst, runtime_address, segment_address);

        // Handle special cases
        switch (inst->opcode) {
        default:
            break;
        }

        offset += IA32_inst.length;
        runtime_address += IA32_inst.length;
        current_inst++;

        // TODO : write the buffer to file, clear buffer, repeat...
        // TODO : edit addresses pointing to the code segment

        if (size <= offset) {
            break; // All instructions have been parsed
        }
    }
}
