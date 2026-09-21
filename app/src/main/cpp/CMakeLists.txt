cmake_minimum_required(VERSION 3.22.1)
project(syshook_test C)

add_subdirectory(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../syshook
    ${CMAKE_CURRENT_BINARY_DIR}/syshook
)

add_library(native_test SHARED native_test.c)

find_library(log-lib log)

target_link_libraries(native_test PRIVATE syshook ${log-lib})
