
add_library(ComputerTransassembler_lib
        ComputerOpcodesInfo.h
        ComputerOpcodesInfo.cpp
        Instruction.h
        IA32Mapping.h
        IA32Mapping.cpp
        Transassembler.h
        Transassembler.cpp)

target_link_libraries(ComputerTransassembler_lib PRIVATE Zydis elfio::elfio)
