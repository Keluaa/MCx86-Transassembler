cmake_minimum_required(VERSION 3.8)
project("ComputerTransassembler")

set(CMAKE_CXX_STANDARD 20)

# Zydis
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory(dependencies/zydis)

# ELFIO
add_subdirectory(dependencies/elfio)

# ComputerTransassembler Lib
add_subdirectory(transassembler)

# ComputerTransassembler
add_executable(ComputerTransassembler
        ComputerTransassembler.cpp)

target_link_libraries(ComputerTransassembler PRIVATE Zydis ComputerTransassembler_lib elfio::elfio)

# AssemblyPreprocessor
add_subdirectory(assembly_preprocessor)

# ProgramCore
add_subdirectory(ProgramCore)

# Tests
add_subdirectory(tests)
