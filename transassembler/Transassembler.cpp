﻿
#include <cstdio>
#include <cstring>

#include "Transassembler.h"


Transassembler::Transassembler(const IA32::Mapping* mapping, const uint8_t* data, const size_t size, const uint64_t addr)
    : mapping(mapping), data(data), size(size), segment_address(addr), decoder()
{
    // x86 with 32-bit addressing
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
}


/**
 * Parses through all instructions to create a map of all instructions with jumps and to which instruction they jump
 * to. Also builds the map from instruction address to instruction index (instructions_numbers).
 *
 * This operation allows to freely edit instructions without worrying about size changes. Since most jumps are
 * relative offsets from the current instruction, we cannot change the size of an instruction without changing the
 * jumps offsets. This is equivalent to going back to using assembly labels.
 * However doing this implies that we know all offsets we jump to at compile time, meaning that any jumps using
 * register values cannot be processed here.
 */
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


bool Transassembler::is_instruction_a_jump(const ZydisDecodedInstruction& inst) {
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


/**
 * Returns the absolute address the instruction jumps to.
 * If the jump is determined at run time (the address is in a register) an assertion fails.
 * If the instruction doesn't jump, or if the jump address is stored in the stack, then it returns 0.
 *
 * @param inst The jumping instruction
 * @param addr The absolute address of the instruction (not counting its length)
 * @return The absolute address of the jump, or 0
 */
ZyanUSize Transassembler::get_jump_address(const ZydisDecodedInstruction& inst, const ZyanUSize inst_address)
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
            throw TransassemblingException("Absolute address (LOOP) calculation failed.", inst, inst_address);
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


bool Transassembler::does_instruction_branches(const ZydisDecodedInstruction& inst) {
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


void Transassembler::convert_instructions(std::filebuf& out_file)
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
            throw ConversionException(runtime_address, "Instruction decoding error.");
        }

        convert_instruction(IA32_inst, inst, runtime_address, segment_address);

        // Handle special cases
        switch (inst.opcode) {
        default:
            // TODO : transform some instructions, such as 'XCHG EAX, EAX' to 'NOP'
            break;
        }

        if (processed_jumping_instructions.contains(current_inst)) {
            // TODO : make sure this covers all cases
            inst.address_value = segment_address + processed_jumping_instructions[current_inst];
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


Register Transassembler::scale_register(uint8_t index, bool operand_size_override, bool operand_byte_size_override,
                                        const uint32_t virtual_address)
{
    if (operand_byte_size_override) {
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
    else if (operand_size_override) {
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

    throw ConversionException(virtual_address, "Invalid register index: %d", index);
}


Register Transassembler::operand_to_register(IA32::Operand register_operand, bool operand_size_override, bool operand_byte_size_override,
                                             const uint32_t virtual_address)
{
    using IA32::Operand;

    switch (register_operand) {
    case Operand::AL:  return Register::AL;
    case Operand::AH:  return Register::AX;
    case Operand::EAX: return Register::EAX;

    case Operand::CL:  return Register::CL;
    case Operand::ECX: return Register::ECX;

    case Operand::DL:  return Register::DL;
    case Operand::EDX: return Register::EDX;

    case Operand::A: return scale_register(0, operand_size_override, operand_byte_size_override, virtual_address);
    case Operand::C: return scale_register(1, operand_size_override, operand_byte_size_override, virtual_address);
    case Operand::D: return scale_register(2, operand_size_override, operand_byte_size_override, virtual_address);
    case Operand::B: return scale_register(3, operand_size_override, operand_byte_size_override, virtual_address);

    default:
        throw ConversionException(virtual_address, "The custom output register must be a register operand.");
    }
}


uint32_t Transassembler::operand_to_immediate(IA32::Operand immediate_operand, const ZydisDecodedOperand& operand, const uint32_t virtual_address)
{
    using IA32::Operand;

    switch (immediate_operand) {
    case Operand::imm8:  return (uint8_t)  operand.imm.value.u;
    case Operand::imm16: return (uint16_t) operand.imm.value.u;
    case Operand::imm32: return (uint32_t) operand.imm.value.u;

    case Operand::imm:
        switch (operand.element_size) {
        case 8:  return (uint8_t)  operand.imm.value.u;
        case 16: return (uint16_t) operand.imm.value.u;
        case 32: return (uint32_t) operand.imm.value.u;

        default:
            throw ConversionException(virtual_address, "Unknown third immediate operand size: %d\n", operand.element_size);
        }

    default:
        throw ConversionException(virtual_address, "Invalid third operand type: %d\n", immediate_operand);
    }
}


void Transassembler::convert_operand(const ZydisDecodedInstruction& IA32inst, const IA32::Inst& extract_data,
                                     Instruction& inst,
                                     uint32_t virtual_address, uint32_t segment_base_address, uint8_t op_index,
                                     const IA32::Operand& inst_operand, Instruction::Operand& op,
                                     bool rm_is_register_operand, uint8_t rm_index, uint8_t sib_scale)
{
    using IA32::Operand;

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
        op.reg = scale_register(inst.opcode & 0b111, false, true, virtual_address);
        break;

    case Operand::reg:
        op.type = OpType::REG;
        // The register index is encoded in the first 3 bits of the opcode
        op.reg = scale_register(inst.opcode & 0b111, override_16bits, override_8bits, virtual_address);
        break;

    case Operand::r8:
        op.type = OpType::REG;
        op.reg = scale_register(ZydisRegisterGetId(IA32inst.operands[op_index].reg.value),
                                false, true, virtual_address);
        break;

    case Operand::r16:
        op.type = OpType::REG;
        op.reg = scale_register(ZydisRegisterGetId(IA32inst.operands[op_index].reg.value),
                                true, false, virtual_address);
        break;

    case Operand::r32:
        op.type = OpType::REG;
        op.reg = scale_register(ZydisRegisterGetId(IA32inst.operands[op_index].reg.value),
                                false, false, virtual_address);
        break;

    case Operand::r:
        op.type = OpType::REG;
        op.reg = scale_register(ZydisRegisterGetId(IA32inst.operands[op_index].reg.value),
                                override_16bits, override_8bits, virtual_address);
        break;

    case Operand::rm8:
        if (rm_is_register_operand) {
            op.type = OpType::REG;
            op.reg = scale_register(rm_index, false, true, virtual_address);
        }
        else {
            // Since the operand size is not encoded into the memory operands, the operand size must match.
            if (!override_8bits || override_16bits) {
                throw ConversionException(virtual_address, "The operand size should be 8 bits.");
            }
            op.type = OpType::MEM;
            op.reg = static_cast<Register>((rm_index & 0b111) | (sib_scale << 3));
        }
        break;

    case Operand::rm16:
        if (rm_is_register_operand) {
            op.type = OpType::REG;
            op.reg = scale_register(rm_index, true, false, virtual_address);
        }
        else {
            // Since the operand size is not encoded into the memory operands, the operand size must match.
            if (override_8bits || !override_16bits) {
                throw ConversionException(virtual_address, "The operand size should be 16 bits.");
            }
            op.type = OpType::MEM;
            op.reg = static_cast<Register>((rm_index & 0b111) | (sib_scale << 3));
        }
        break;

    case Operand::rm:
        if (rm_is_register_operand) {
            op.type = OpType::REG;
            op.reg = scale_register(rm_index, override_16bits, override_8bits, virtual_address);
        }
        else {
            // Since the operand size is not encoded into the memory operands, the operand size must match.
            if (override_8bits) {
                throw ConversionException(virtual_address, "The operand size should not be 8 bits.");
            }
            op.type = OpType::MEM;
            op.reg = static_cast<Register>((rm_index & 0b111) | (sib_scale << 3));
        }
        break;

    case Operand::m8:
        // Since the operand size is not encoded into the memory operands, the operand size must match.
        if (!override_8bits || override_16bits) {
            throw ConversionException(virtual_address, "The operand size should be 8 bits.");
        }
    case Operand::m:
        op.type = OpType::MEM;
        op.reg = static_cast<Register>((rm_index & 0b111) | (sib_scale << 3));
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


void Transassembler::extract_mod_rm_sib_bytes(const ZydisDecodedInstruction& IA32inst, Instruction& inst,
                                              bool& rm_is_register_operand, uint8_t& register_index, uint8_t& sib_scale)
{
    auto modrm = IA32inst.raw.modrm;
    auto sib = IA32inst.raw.sib;
    auto disp = IA32inst.raw.disp;

    if (modrm.mod == 0b11) {
        // The Mod r/m byte describes a register operand
        rm_is_register_operand = true;
        register_index = modrm.rm;
        inst.compute_address = false;
    }
    else if (modrm.mod == 0b00 && modrm.rm == 0b101) {
        // Mod r/m byte, alone with no register. There is only a displacement
        inst.address_value = disp.value;
        inst.compute_address = true;
    }
    else {
        // The Mod r/m byte describes a memory operand

        inst.compute_address = true;

        bool displacement_present = false;

        if (modrm.rm == 0b100) {
            // There is a SIB byte
            inst.scaled_reg_present = true;
            inst.scaled_reg = sib.index;
            sib_scale = sib.scale;

            if (sib.base == 0b101) {
                switch (modrm.mod) {
                case 0b00:
                    // No base, with 32 bit displacement
                    inst.base_reg_present = false;
                    inst.address_value = disp.value;
                    break;

                case 0b01:
                    // With EBP base, with 8 bit displacement, converted to 32 bits
                    inst.base_reg_present = true;
                    register_index = uint8_t(Register::EBP);
                    displacement_present = true;
                    inst.address_value = int32_t(int8_t(uint8_t(disp.value)));
                    break;

                case 0b10:
                    // With EBP base, with 32 bit displacement
                    inst.base_reg_present = true;
                    register_index = uint8_t(Register::EBP);
                    displacement_present = true;
                    inst.address_value = disp.value;
                    break;
                }
            }
            else {
                // Normal base specification
                inst.base_reg_present = true;
                register_index = sib.base;
            }
        }
        else {
            // Mod r/m byte alone
            inst.scaled_reg_present = true;
            inst.scaled_reg = modrm.rm;
        }

        if (!displacement_present) {
            // Displacement (if it has not been already specified by the SIB byte)
            switch (modrm.mod) {
            case 0b00:
                break;

            case 0b01:
                // 8 bits displacement, converted to 32 bits
                inst.address_value = int32_t(int8_t(uint8_t(disp.value)));
                break;

            case 0b10:
                // 32 bits displacement
                inst.address_value = disp.value;
                break;
            }
        }
    }
}


/**
 * Performs additional changes to some instructions.
 *
 * Some instructions like SETcc or Jcc have a lot of information stored in their opcode, at the expense of having a lot
 * of possible opcodes in the instruction set. Instead, we have a single opcode for those, and the variant of the
 * operation is stored in the immediate value.
 */
void Transassembler::post_conversion(const ZydisDecodedInstruction& IA32inst, Instruction& inst)
{
    // TODO : after the merge, use the actual opcode enum here
    switch (inst.opcode) {
    case 40: // ROT
        if (inst.immediate_value != 0) {
            inst.immediate_value &= 0b11111; // Make sure to keep only the useful bits
            inst.immediate_value |= 1 << 5; // Use the immediate value
        }

        switch (IA32inst.mnemonic) {
        case ZYDIS_MNEMONIC_RCL: inst.immediate_value |= 1 << 7; // Use the carry
        case ZYDIS_MNEMONIC_ROL: inst.immediate_value |= 1 << 6; // Rotate left
            break;

        case ZYDIS_MNEMONIC_RCR: inst.immediate_value |= 1 << 7; // Use the carry
        case ZYDIS_MNEMONIC_ROR: inst.immediate_value |= 0 << 6; // Rotate right
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
        case ZYDIS_MNEMONIC_SALC: inst.immediate_value |= 1 << 7; // Signed operation
        case ZYDIS_MNEMONIC_SHL:  inst.immediate_value |= 1 << 6; // Rotate left
            break;

        case ZYDIS_MNEMONIC_SAR: inst.immediate_value |= 1 << 7; // Signed operation
        case ZYDIS_MNEMONIC_SHR: inst.immediate_value |= 0 << 6; // Rotate right
            break;

        default: break; // This case will never happen just trust me
        }
        break;

    case 44: // SETcc
        // All opcodes are merged into one, and the condition is encoded in the immediate
        switch (IA32inst.mnemonic) {
        case ZYDIS_MNEMONIC_SETNBE: inst.immediate_value = 0b0000; break; // Above | Not below or equal
        case ZYDIS_MNEMONIC_SETNB:  inst.immediate_value = 0b0001; break; // Above or equal | Not below | Not carry
        case ZYDIS_MNEMONIC_SETB:   inst.immediate_value = 0b0010; break; // Below | Carry | Not above or equal
        case ZYDIS_MNEMONIC_SETBE:  inst.immediate_value = 0b0011; break; // Below or equal | Not above
        case ZYDIS_MNEMONIC_SETZ:   inst.immediate_value = 0b0100; break; // Equal | Zero
        case ZYDIS_MNEMONIC_SETNLE: inst.immediate_value = 0b0101; break; // Greater | Not less or equal
        case ZYDIS_MNEMONIC_SETNL:  inst.immediate_value = 0b0110; break; // Greater or Equal | Not less
        case ZYDIS_MNEMONIC_SETL:   inst.immediate_value = 0b0111; break; // Less | Not greater or equal
        case ZYDIS_MNEMONIC_SETLE:  inst.immediate_value = 0b1000; break; // Less or equal | Not greater
        case ZYDIS_MNEMONIC_SETNZ:  inst.immediate_value = 0b1001; break; // Not equal | Not zero
        case ZYDIS_MNEMONIC_SETNO:  inst.immediate_value = 0b1010; break; // Not overflow
        case ZYDIS_MNEMONIC_SETNP:  inst.immediate_value = 0b1011; break; // Not parity | Parity odd
        case ZYDIS_MNEMONIC_SETNS:  inst.immediate_value = 0b1100; break; // Not sign
        case ZYDIS_MNEMONIC_SETO:   inst.immediate_value = 0b1101; break; // Overflow
        case ZYDIS_MNEMONIC_SETP:   inst.immediate_value = 0b1110; break; // Parity | Parity even
        case ZYDIS_MNEMONIC_SETS:   inst.immediate_value = 0b1111; break; // Sign
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
        case ZYDIS_MNEMONIC_JNBE:  inst.immediate_value = 0b00000; break; // Above | Not below or equal
        case ZYDIS_MNEMONIC_JNB:   inst.immediate_value = 0b00001; break; // Above or equal | Not below | Not carry
        case ZYDIS_MNEMONIC_JB:    inst.immediate_value = 0b00010; break; // Below | Carry | Not above or equal
        case ZYDIS_MNEMONIC_JBE:   inst.immediate_value = 0b00011; break; // Below or equal | Not above
        case ZYDIS_MNEMONIC_JZ:    inst.immediate_value = 0b00100; break; // Equal | Zero
        case ZYDIS_MNEMONIC_JNLE:  inst.immediate_value = 0b00101; break; // Greater | Not less or equal
        case ZYDIS_MNEMONIC_JNL:   inst.immediate_value = 0b00110; break; // Greater or Equal | Not less
        case ZYDIS_MNEMONIC_JL:    inst.immediate_value = 0b00111; break; // Less | Not greater or equal
        case ZYDIS_MNEMONIC_JLE:   inst.immediate_value = 0b01000; break; // Less or equal | Not greater
        case ZYDIS_MNEMONIC_JNZ:   inst.immediate_value = 0b01001; break; // Not equal | Not zero
        case ZYDIS_MNEMONIC_JNO:   inst.immediate_value = 0b01010; break; // Not overflow
        case ZYDIS_MNEMONIC_JNP:   inst.immediate_value = 0b01011; break; // Not parity | Parity odd
        case ZYDIS_MNEMONIC_JNS:   inst.immediate_value = 0b01100; break; // Not sign
        case ZYDIS_MNEMONIC_JO:    inst.immediate_value = 0b01101; break; // Overflow
        case ZYDIS_MNEMONIC_JP:    inst.immediate_value = 0b01110; break; // Parity | Parity even
        case ZYDIS_MNEMONIC_JS:    inst.immediate_value = 0b01111; break; // Sign
        case ZYDIS_MNEMONIC_JCXZ:  inst.immediate_value = 0b10000; break; // CX register is zero
        case ZYDIS_MNEMONIC_JECXZ: inst.immediate_value = 0b10001; break; // ECX register is zero
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
void Transassembler::convert_instruction(const ZydisDecodedInstruction& IA32inst, Instruction& inst,
                                         uint32_t virtual_address, uint32_t segment_base_address) const
{
    if (!mapping->is_opcode_known(IA32inst.opcode)) {
        throw ConversionException(virtual_address, "Unknown opcode: %d (%s)\n", IA32inst.opcode, ZydisMnemonicGetString(IA32inst.mnemonic));
    }

    // TODO : REP prefix, checked with IA32inst.attributes & ZYDIS_ATTRIB_HAS_REP ou ZYDIS_ATTRIB_HAS_REPE

    uint16_t opcode = IA32inst.opcode;
    opcode |= IA32inst.opcode_map == ZYDIS_OPCODE_MAP_0F ? 0x0F00 : 0x0000;
    if (mapping->has_opcode_reg_extension(IA32inst.opcode)) {
        // /digit extension from the reg field of the Mod r/m byte
        opcode += IA32inst.raw.modrm.reg << 12;
    }

    const IA32::Inst& extract_data = mapping->get_extraction_data(opcode);

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
    uint8_t register_index = 0, sib_scale = 0;
    if (extract_data.has_mod_byte) {
        extract_mod_rm_sib_bytes(IA32inst, inst, rm_is_register_operand, register_index, sib_scale);
    }

    if (extract_data.has_mod_byte != bool(IA32inst.attributes & ZYDIS_ATTRIB_HAS_MODRM)) {
        throw ConversionException(virtual_address, "Invalid implementation, extraction info is different from the one of the decompiler.");
    }

    // First operand
    convert_operand(IA32inst, extract_data, inst, virtual_address, segment_base_address, 0,
                    extract_data.operand_1, inst.op1, rm_is_register_operand, register_index, sib_scale);

    // Second operand
    convert_operand(IA32inst, extract_data, inst, virtual_address, segment_base_address, 1,
                    extract_data.operand_2, inst.op2, rm_is_register_operand, register_index, sib_scale);

    // Third immediate operand
    if (extract_data.operand_3_imm != IA32::Operand::None) {
        if (inst.immediate_value != 0) {
            throw ConversionException(virtual_address, "Immediate value already used: %d", inst.immediate_value);
        }

        if (IA32inst.operands[2].type != ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            throw ConversionException(virtual_address, "Wrong third immediate operand type.");
        }

        inst.immediate_value = operand_to_immediate(extract_data.operand_3_imm, IA32inst.operands[2], virtual_address);
    }

    inst.op1.read = extract_data.read_operand_1;
    inst.op2.read = extract_data.read_operand_2;

    inst.write_ret1_to_op1 = extract_data.write_ret_1_to_op_1;
    inst.write_ret2_to_op2 = extract_data.write_ret_2_to_op_2;

    inst.write_ret2_to_register = extract_data.write_ret_2_register;
    inst.scale_output_override = extract_data.write_ret_register_scale;

    if (extract_data.write_ret_out_register != IA32::Operand::None) {
        inst.register_out = operand_to_register(extract_data.write_ret_out_register, inst.operand_size_override, inst.operand_byte_size_override, virtual_address);
    }

    inst.get_flags = extract_data.get_flags;
    inst.get_CR0 = extract_data.get_CR0;

    post_conversion(IA32inst, inst);
}