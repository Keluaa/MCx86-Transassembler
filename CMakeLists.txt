cmake_minimum_required(VERSION 3.8)
project("ComputerTransassembler")

set(CMAKE_CXX_STANDARD 20)

# Zydis
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("dependencies/zydis")

# ELFIO
include_directories(ComputerTransassembler "dependencies/elfio/elfio")

# ComputerTransassembler
add_executable(ComputerTransassembler
        ComputerTransassembler.cpp
        Transassembler.cpp
        Transassembler.h
        IA32Mapping.cpp
        IA32Mapping.h
        Instruction.h)

target_link_libraries(ComputerTransassembler PRIVATE "Zydis")

# ProgramCore
add_subdirectory(ProgramCore)

# Tests
add_subdirectory(tests)
