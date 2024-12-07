# To install dependencies:
# $ sudo apt install llvm-dev clang libbpf-dev bpftool pkg-config
# Sample command to make
# $ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=YES -Bbuild
# $ cd build && make
cmake_minimum_required(VERSION 3.22)
project(tangram_ebpf LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS)
set(CMAKE_C_COMPILER "/usr/bin/clang")
set(CMAKE_C_FLAGS "-g -O2 -target bpf -emit-llvm -D__TARGET_ARCH_x86")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(LLVM REQUIRED CONFIG)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/elf)

# If make complains `asm/types.h` not found, install gcc-multilib as below
# `sudo apt-get install -y gcc-multilib`
include_directories(${LLVM_INCLUDE_DIRS} "/usr/include/bpf" "src")

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

list(APPEND BPF_LIST "sched_process_exec")
foreach(bpf IN LISTS BPF_LIST)
    # clang output is an object file.
    add_library(${bpf} OBJECT src/${bpf}/probe.bpf.c)

    add_custom_target(${bpf}_skel ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/elf/${bpf}.skel.h)
    add_custom_command(OUTPUT elf/${bpf}.skel.h
        COMMAND  /usr/bin/llc -march=bpf -mcpu=probe -filetype=obj -o elf/${bpf}.elf $<TARGET_OBJECTS:${bpf}>
        COMMAND  /usr/sbin/bpftool gen skeleton ${CMAKE_CURRENT_BINARY_DIR}/elf/${bpf}.elf > ${CMAKE_CURRENT_BINARY_DIR}/elf/${bpf}.skel.h)
endforeach()
