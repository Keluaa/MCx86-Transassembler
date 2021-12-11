    .text
filler:
    JMP label
label:
    JMP test
test:
    .intel_syntax noprefix
#include "instruction.S"
