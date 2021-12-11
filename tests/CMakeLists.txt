
add_executable(InstConv_Tests
        InstructionConversionTests.cpp)

include_directories(InstConv_Tests "./" "../transassembler")
target_link_libraries(InstConv_Tests PRIVATE ComputerTransassembler_lib Zydis elfio::elfio)
