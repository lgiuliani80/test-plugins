cmake_minimum_required(VERSION 3.15)
project(my_sha1 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Place every build artifact (executable, shared libraries, DLLs) in the
# same directory so that my_sha1 can load plugins with a bare relative path.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})   # .exe / .dll (Windows)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})   # .so         (Linux/macOS)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(my_sha1 main.c)

# CMAKE_DL_LIBS is "dl" on Linux, empty on macOS and Windows – always safe
# to pass unconditionally.
target_link_libraries(my_sha1 PRIVATE ${CMAKE_DL_LIBS})

# ── SHA-1 plugins (shared libraries) ─────────────────────────────────────────
# Strip the default "lib" prefix on ELF targets so the filename matches what
# the user passes on the command line (sha1basic.so, not libsha1basic.so).

add_library(sha1basic SHARED sha1basic.c)
set_target_properties(sha1basic PROPERTIES PREFIX "")

add_library(sha1intrinsics-x86 SHARED sha1instrinsics-x86.c)
set_target_properties(sha1intrinsics-x86 PROPERTIES PREFIX "")

# GCC/Clang: sha1_compress already carries __attribute__((target("sha,sse4.1")))
# so no TU-level ISA flag is required.
# MSVC: the SHA-NI intrinsics in <immintrin.h> are available without a specific
# /arch: flag; the CPU capability is assumed at runtime.
# Nothing extra needed here for either compiler.

# ── Pure NASM plugin ─────────────────────────────────────────────────────────
# CMake's ASM_NASM support produces object files but cannot link shared libs
# directly.  We therefore assemble manually with a custom command and then
# hand the resulting object to the C linker via an OBJECT library + SHARED lib.

if(WIN32)
    set(NASM_FORMAT win64)
else()
    set(NASM_FORMAT elf64)
endif()

find_program(NASM_EXECUTABLE nasm REQUIRED)

set(NASM_OBJ ${CMAKE_BINARY_DIR}/sha1asm-x86.o)
add_custom_command(
    OUTPUT  ${NASM_OBJ}
    COMMAND ${NASM_EXECUTABLE} -f ${NASM_FORMAT} -o ${NASM_OBJ}
            ${CMAKE_CURRENT_SOURCE_DIR}/sha1asm-x86.asm
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/sha1asm-x86.asm
    COMMENT "Assembling sha1asm-x86.asm (${NASM_FORMAT})"
)
add_custom_target(sha1asm-x86-obj DEPENDS ${NASM_OBJ})

add_library(sha1asm-x86 SHARED ${NASM_OBJ})
add_dependencies(sha1asm-x86 sha1asm-x86-obj)
set_target_properties(sha1asm-x86 PROPERTIES
    PREFIX         ""
    LINKER_LANGUAGE C
)
# Remove the default -lstdc++ / -lm that CMake injects for C targets and
# suppress the executable-stack linker warning generated from NASM output.
if(UNIX AND NOT APPLE)
    target_link_options(sha1asm-x86 PRIVATE -Wl,-z,noexecstack)
endif()
