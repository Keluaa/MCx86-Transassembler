cmake_minimum_required(VERSION 3.8)
project("ComputerTransassembler")

set(CMAKE_CXX_STANDARD 20)

# Zydis
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("dependencies/zydis")

# ComputerTransassembler Lib
add_library(ComputerTransassembler_lib
        ComputerOpcodesInfo.h
        ComputerOpcodesInfo.cpp
        Instruction.h
        IA32Mapping.h
        IA32Mapping.cpp
        Transassembler.h
        Transassembler.cpp)

target_link_libraries(ComputerTransassembler_lib PRIVATE "Zydis")

# ComputerTransassembler
add_executable(ComputerTransassembler
        ComputerTransassembler.cpp)

target_link_libraries(ComputerTransassembler PRIVATE "Zydis" ComputerTransassembler_lib)

# ELFIO
include_directories(ComputerTransassembler "dependencies/elfio/elfio")

# AssemblyPreprocessor
add_subdirectory(assembly_preprocessor)

# ProgramCore
add_subdirectory(ProgramCore)

# Tests
add_subdirectory(tests)
