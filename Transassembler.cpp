
#include <cstdio>
#include <cstring>

#include "Transassembler.h"


Transassembler::Transassembler(const uint8_t* data, const size_t size, const uint64_t addr)
    : data(data), size(size), segment_address(addr), decoder()
{
    // x86 with 32-bit addressing
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
}


void Transassembler::process_jumping_instructions()
{
    // Maps the instruction targets to their jumping instructions.
    std::unordered_multimap<ZyanUSize, uint32_t> unprocessed_jump_targets;

    // TODO : handle references to memory in the code, such as in the Mod r/m + SIB bytes and moffs operands (with the CS prefix)

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
        if (does_instruction_branches(inst)) {
            // If this fails then there is an instruction missing in the cases above
            throw TransassemblingException("Unhandled jumping instruction.", inst);
        }
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
                throw TransassemblingException("Operand should be relative.", inst, inst_address);
            }

            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &op, inst_address, &abs_addr))) {
                throw TransassemblingException("Absolute address (relative offset) calculation failed.", inst, inst_address);
            }
        }
        else {
            // Address in the Mod r/m. If it uses an address from a register, then we have a problem.
            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &op, inst_address, &abs_addr))) {
                // What we don't allow : jumping to instructions outside the pre-decoded instructions area, or using
                //      a pre-determined offset stored in the data section of the memory (ROM or RAM)
                // What we allow : jumping using an offset table stored in ROM which has been corrected
                // To reflect those conditions, jumps from a memory offset (or absolute address) accessed using a 4
                // times scaled index from a base is allowed.

                if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.encoding == ZYDIS_OPERAND_ENCODING_MODRM_RM
                        && op.mem.type == ZYDIS_MEMOP_TYPE_MEM && op.mem.segment == ZYDIS_REGISTER_DS
                        && op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index != ZYDIS_REGISTER_NONE
                        && op.mem.scale == 4 && op.mem.disp.has_displacement) {
                    break; // Is ok.
                }
                else {
                    throw TransassemblingException("Absolute address (mod r/m) calculation failed.", inst, inst_address);
                }
            }
        }
        break;
    }

    case ZYDIS_MNEMONIC_INT:  // not a jump we want to process
    case ZYDIS_MNEMONIC_IRET: // EIP is popped from the stack
        break;

    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, inst.operands + 0, inst_address, &abs_addr))) {
            throw TransassemblingException("Absolute address (LOOP*) calculation failed.", inst, inst_address);
        }
        break;

    case ZYDIS_MNEMONIC_RET:
        if (inst.operand_count == 1) {
            // Relative offset from the immediate
            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, inst.operands + 0, inst_address, &abs_addr))) {
                throw TransassemblingException("Absolute address (RET) calculation failed.", inst, inst_address);
            }
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
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, inst.operands + 0, inst_address, &abs_addr))) {
            throw TransassemblingException("Absolute address (relative offset) calculation failed.", inst, inst_address);
        }
        break;

    default:
        break;
    }

    return abs_addr;
}


constexpr bool Transassembler::does_instruction_branches(const ZydisDecodedInstruction& inst) {
    return inst.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE;
}


void Transassembler::update_labels_section(const ELFIO::endianess_convertor& conv, uint8_t* labels_data, size_t labels_size)
{
    uint32_t* p_data = reinterpret_cast<uint32_t*>(labels_data);
	uint32_t* p_data_end = p_data + (labels_size / sizeof(uint32_t));
	
	for (int i = 0; p_data < p_data_end; i++, p_data++) {
		uint32_t label = conv(*p_data);
		if (instructions_numbers.contains(label)) {
			*p_data = conv(instructions_numbers[label]);
		}
		else {
			// Missing instruction target
			printf("WARNING: label target not found: 0x%x\n", label);
            *p_data = 0;
		}
	}
}


void Transassembler::convert_instructions(const IA32::Mapping& mapping, std::filebuf& out_file)
{
    const size_t BUFFER_SIZE = 512;

    ZydisDecodedInstruction IA32_inst;
    ZyanU64 runtime_address = segment_address;
    ZyanUSize offset = 0;
    uint32_t current_inst = 0;

    size_t buffer_pos = 0;

    while (offset < size) {
        Instruction inst{};

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, size - offset, &IA32_inst))) {
            // TODO : problem
            break;
        }

        mapping.convert_instruction(IA32_inst, inst, runtime_address, segment_address);

        // Handle special cases
        switch (inst.opcode) {
        default:
            // TODO : transform some instructions, such as 'XCHG EAX, EAX' to 'NOP'
            break;
        }

        offset += IA32_inst.length;
        runtime_address += IA32_inst.length;
        current_inst++;

        // TODO : edit addresses pointing to the code segment

        // Write the instruction to the file buffer
        out_file.sputn(reinterpret_cast<const char*>(&inst), sizeof(Instruction));
        buffer_pos++;

        if (buffer_pos > BUFFER_SIZE) {
            // Write the buffer to the file (flush)
            out_file.pubsync();
            buffer_pos = 0;
        }
    }
}
