
set(Program_Core_Sources
        start.c
        fib.c)

set(Program_Core_Linker_Script linking.ld)

set(Program_Core_Executable Program_core.exe)

# We want a static binairy (no relocation needed anywhere) for x86
set(Program_Core_Compile_Flags
        -m32                    # Compile for the x86 Architecture
        -ffreestanding          # No external or standard library needed
        -fno-pic                # Don't generate Position Independent Code (which uses the Global Offset Table)
        -fno-pie                # Don't generate a Position Independent Executable
        -Os)                    # Optimize for speed and space. Has the advantages of -O2 but without aligning functions
                                # jumps, etc... which makes our job easier

# Do not link with the C library, and use our custom startup function
set(Program_Core_Link_Flags
        -static                 # Produce a static file
        -nolibc                 # No linking with the Standard C Library
        -nostartfiles           # Do not use the standard startup functions
        --entry=_start)         # Use our _start function as the entry point

set(Program_Core_CMD
        gcc
        ${Program_Core_Compile_Flags}
        ${Program_Core_Link_Flags}
        -T ${Program_Core_Linker_Script} # Build the output file using our custom linker script
        -o ${Program_Core_Executable}
        ${Program_Core_Sources})

# Use WSL in order to use gcc without any Windows related problems
add_custom_target(Program_core
        COMMAND wsl ${Program_Core_CMD}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/ProgramCore
        SOURCES ${Program_Core_Sources} # only useful for the IDE
        COMMENT "Creating the core executable..."
        BYPRODUCTS ${Program_Core_Executable}
        VERBATIM
        USES_TERMINAL)
