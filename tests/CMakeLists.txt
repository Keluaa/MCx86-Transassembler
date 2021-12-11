
add_executable(InstConv_Tests
        InstructionConversionTests.cpp)

include_directories(InstConv_Tests "../dependencies/elfio/elfio")
include_directories(InstConv_Tests "./")
target_link_libraries(InstConv_Tests PRIVATE "Zydis" ComputerTransassembler_lib)
