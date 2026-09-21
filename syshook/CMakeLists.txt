cmake_minimum_required(VERSION 3.22.1)
project(syshook C ASM)

add_library(syshook STATIC
    src/syshook.c
    src/bpf.c
    src/handler.c
    src/trampoline.S
)

target_include_directories(syshook PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(syshook PRIVATE
    -Wall -Wextra -Wshadow -O2 -fvisibility=hidden
)

set_target_properties(syshook PROPERTIES
    C_STANDARD 11
    POSITION_INDEPENDENT_CODE ON
)
