# MCx86-Transassembler

Compiles a C program into x86 encoded assembly in an ELF file with a specific structure.

The memory structure of the executable file is split into files, which can then be given as input to [MCx86](https://github.com/Keluaa/MCx86).

The instructions in the code segment are all converted into instructions understandable by MCx86.
Those new instructions are not encoded, and have an effective size of 1 byte, which makes it so that MCx86 doesn't need a decoder.
However since their size changed, all jumps in the code needs to be recalculated.

This is a work in progress.
