cmake_minimum_required(VERSION 3.15)
project(my_sha1 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Place every build artifact (executable, shared libraries, DLLs) in the
# same directory so that my_sha1 can load plugins with a bare relative path.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Multi-config generators (Visual Studio, Ninja Multi-Config) append a
# per-configuration subdirectory (e.g. Release/) by default.  Override that
# so all artifacts land in the same directory regardless of generator.
foreach(_cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_cfg} ${CMAKE_BINARY_DIR})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${_cfg} ${CMAKE_BINARY_DIR})
endforeach()

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

# x64-only plugins: SSE intrinsics and NASM assembly require an x86_64 host.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")

    add_library(sha1intrinsics-sse SHARED sha1instrinsics-sse.c)
    set_target_properties(sha1intrinsics-sse PROPERTIES PREFIX "")

    # GCC/Clang: sha1_compress already carries __attribute__((target("sha,sse4.1")))
    # so no TU-level ISA flag is required.
    # MSVC: the SHA-NI intrinsics in <immintrin.h> are available without a specific
    # /arch: flag; the CPU capability is assumed at runtime.
    # Nothing extra needed here for either compiler.

    # ── Pure NASM plugin ─────────────────────────────────────────────────────
    # CMake's ASM_NASM support produces object files but cannot link shared libs
    # directly.  We therefore assemble manually with a custom command and then
    # hand the resulting object to the C linker via an OBJECT library + SHARED lib.

    if(WIN32)
        set(NASM_FORMAT win64)
    else()
        set(NASM_FORMAT elf64)
    endif()

    find_program(NASM_EXECUTABLE nasm REQUIRED)

    set(NASM_OBJ ${CMAKE_BINARY_DIR}/sha1asm-x64.o)
    add_custom_command(
        OUTPUT  ${NASM_OBJ}
        COMMAND ${NASM_EXECUTABLE} -f ${NASM_FORMAT} -o ${NASM_OBJ}
                ${CMAKE_CURRENT_SOURCE_DIR}/sha1asm-x64.asm
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/sha1asm-x64.asm
        COMMENT "Assembling sha1asm-x64.asm (${NASM_FORMAT})"
    )
    add_custom_target(sha1asm-x64-obj DEPENDS ${NASM_OBJ})

    add_library(sha1asm-x64 SHARED ${NASM_OBJ})
    add_dependencies(sha1asm-x64 sha1asm-x64-obj)
    set_target_properties(sha1asm-x64 PROPERTIES
        PREFIX         ""
        LINKER_LANGUAGE C
    )
    # Remove the default -lstdc++ / -lm that CMake injects for C targets and
    # suppress the executable-stack linker warning generated from NASM output.
    if(UNIX AND NOT APPLE)
        target_link_options(sha1asm-x64 PRIVATE -Wl,-z,noexecstack)
    endif()
    # Link options for MSVC to suppress the default C runtime and specify the Dll entry point.
    if(MSVC)
        target_link_options(sha1asm-x64 PRIVATE /NODEFAULTLIB /ENTRY:DllMain /DEF:"sha1asm-x64.def")
    endif()

else()
    message(STATUS "Non-x64 architecture (${CMAKE_SYSTEM_PROCESSOR}) – skipping sha1intrinsics-sse and sha1asm-x64 plugins")
endif()

# ── .NET + Rust wrapper plugin ────────────────────────────────────────────────
# Both dotnet and cargo are optional; the plugin is simply skipped when either
# tool is absent (e.g. in a minimal CI image).
set(DOTNET_VERSION "net8.0")
find_program(DOTNET_EXECUTABLE dotnet)
find_program(CARGO_EXECUTABLE  cargo)

if(DOTNET_EXECUTABLE AND CARGO_EXECUTABLE)
    set(DOTNET_PROJ ${CMAKE_CURRENT_SOURCE_DIR}/dotnet/src/sha1dotnet.csproj)
    set(DOTNET_OUT  ${CMAKE_CURRENT_SOURCE_DIR}/dotnet/src/bin/Release/${DOTNET_VERSION})

    set(DOTNET_DLL_DST        ${CMAKE_BINARY_DIR}/sha1dotnet.dll)
    set(DOTNET_RUNTIMECFG_DST ${CMAKE_BINARY_DIR}/sha1dotnet.runtimeconfig.json)

    # Step 1 – build the .NET class library and copy artefacts into the binary dir.
    add_custom_command(
        OUTPUT  ${DOTNET_DLL_DST} ${DOTNET_RUNTIMECFG_DST}
        COMMAND ${DOTNET_EXECUTABLE} build ${DOTNET_PROJ} -c Release
        COMMAND ${CMAKE_COMMAND} -E copy
                ${DOTNET_OUT}/sha1dotnet.dll ${DOTNET_DLL_DST}
        COMMAND ${CMAKE_COMMAND} -E copy
                ${DOTNET_OUT}/sha1dotnet.runtimeconfig.json ${DOTNET_RUNTIMECFG_DST}
        DEPENDS ${DOTNET_PROJ}
                ${CMAKE_CURRENT_SOURCE_DIR}/dotnet/src/Functions.cs
        COMMENT "Building .NET plugin (sha1dotnet)"
        VERBATIM
    )
    add_custom_target(sha1dotnet ALL
        DEPENDS ${DOTNET_DLL_DST} ${DOTNET_RUNTIMECFG_DST}
    )

    # Step 2 – build the Rust cdylib that hosts the .NET runtime.
    # On Linux the cargo output is libsha1dotnet_wrapper.so; we copy it without
    # the "lib" prefix so my_sha1 can load it as sha1dotnet_wrapper.so/.dll.
    set(RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/dotnet/rust-wrapper)
    if(WIN32)
        set(RUST_LIB_SRC ${RUST_DIR}/target/release/sha1dotnet_wrapper.dll)
        set(RUST_LIB_DST ${CMAKE_BINARY_DIR}/sha1dotnet_wrapper.dll)
    else()
        set(RUST_LIB_SRC ${RUST_DIR}/target/release/libsha1dotnet_wrapper.so)
        set(RUST_LIB_DST ${CMAKE_BINARY_DIR}/sha1dotnet_wrapper.so)
    endif()

    add_custom_command(
        OUTPUT  ${RUST_LIB_DST}
        COMMAND ${CARGO_EXECUTABLE} build --release
        COMMAND ${CMAKE_COMMAND} -E copy ${RUST_LIB_SRC} ${RUST_LIB_DST}
        WORKING_DIRECTORY ${RUST_DIR}
        DEPENDS ${DOTNET_DLL_DST}
                ${RUST_DIR}/Cargo.toml
                ${RUST_DIR}/src/lib.rs
        COMMENT "Building Rust wrapper plugin (sha1dotnet_wrapper)"
        VERBATIM
    )
    add_custom_target(sha1dotnet_wrapper ALL
        DEPENDS ${RUST_LIB_DST}
    )
else()
    if(NOT DOTNET_EXECUTABLE)
        message(STATUS "dotnet not found – skipping sha1dotnet_wrapper plugin")
    endif()
    if(NOT CARGO_EXECUTABLE)
        message(STATUS "cargo not found – skipping sha1dotnet_wrapper plugin")
    endif()
endif()
