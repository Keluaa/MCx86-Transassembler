
set(Program_Core_Sources
        start.c
        fib.c)

set(Program_Core_Linker_Script linking.ld)

set(Program_Core_Executable Program_core.exe)

set(Program_Core_Compile_Flags)

# Build the list of assembly files by replacing the extension in them
foreach(source_file ${Program_Core_Sources})
    string(REGEX REPLACE "\\.c$" ".s" assembly_file ${source_file})
    list(APPEND Program_Core_Assembly_files ${assembly_file})
endforeach()

if(${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES "aarch64")
	set(Program_Core_Compiler clang)
	set(Program_Core_Env)
else()
	if(NOT ${CMAKE_CXX_COMPILER} MATCHES "c\\+\\+")
		# Use WSL in order to use gcc without any Windows related problems
		set(Program_Core_Env wsl)
	else()
		set(Program_Core_Env)
	endif()
	set(Program_Core_Compiler gcc)
endif()

# We want a static binairy (no relocation needed anywhere) for x86
set(Program_Core_Compile_Flags
        -m32                     # Compile for the x86 Architecture
        -masm=intel              # Use intel assembly format, for easier asm injection
        -ffreestanding           # No external or standard library needed
        -fno-pic                 # Don't generate Position Independent Code (which uses the Global Offset Table)
        -fno-pie                 # Don't generate a Position Independent Executable
        -Os)                     # Optimize for speed and space. Has the advantages of -O2 but without aligning functions
                                 # jumps, etc... which makes our job easier

# Do not link with the C library, and use our custom startup function
set(Program_Core_Link_Flags
        -static                  # Produce a static file
        -nolibc                  # No linking with the Standard C Library
        -nostartfiles            # Do not use the standard startup functions
		-Xlinker -build-id=none) # Don't create a build-id for the file, we don't need it

set(Program_Core_Compile_CMD
		${Program_Core_Env}
        ${Program_Core_Compiler}
        -S                       # Make an assembly file, since there is some preprocessing to be done first.
        ${Program_Core_Compile_Flags}
        ${Program_Core_Sources})

# Get the relative path to the preprocessor from the source directory
file(RELATIVE_PATH Assembly_Preprocessor_relpath ${CMAKE_SOURCE_DIR}/ProgramCore ${PROJECT_BINARY_DIR}/assembly_preprocessor/$<TARGET_FILE_NAME:Assembly_Preprocessor>)

set(Program_Core_Preprocess_CMD
		${Program_Core_Env}
        ${Assembly_Preprocessor_relpath}
        ${Program_Core_Assembly_files})

set(Program_Core_Link_CMD
		${Program_Core_Env}
        ${Program_Core_Compiler}
        ${Program_Core_Compile_Flags}
        ${Program_Core_Link_Flags}
        -T ${Program_Core_Linker_Script} # Build the output file using our custom linker script
        -o ${Program_Core_Executable}
        ${Program_Core_Assembly_files})

add_custom_target(Program_core
        COMMAND ${Program_Core_Compile_CMD}         # Compile the sources into assembly files
        COMMAND ${Program_Core_Preprocess_CMD}      # Preprocess the assembly files
        COMMAND ${Program_Core_Link_CMD}            # Link the assembly files into an executable
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/ProgramCore
        SOURCES ${Program_Core_Sources} 			# Only useful for the IDE
        COMMENT "Creating the core executable..."
        BYPRODUCTS ${Program_Core_Executable} ${Program_Core_Assembly_files}
        VERBATIM
        USES_TERMINAL)

add_dependencies(Program_core Assembly_Preprocessor)

add_custom_target(Program_core_debug
		COMMAND ${Program_Core_Compile_CMD} -g      # Compile the sources into assembly files, with debugging info
		COMMAND ${Program_Core_Link_CMD}            # Link the assembly files into an executable
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/ProgramCore
		SOURCES ${Program_Core_Sources} 			# Only useful for the IDE
		COMMENT "Creating the core executable..."
		BYPRODUCTS ${Program_Core_Executable} ${Program_Core_Assembly_files}
		VERBATIM
		USES_TERMINAL)
