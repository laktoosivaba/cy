# Copyright (c) Pavel Kirienko

cmake_minimum_required(VERSION 3.24)
project(cy_examples CXX)
enable_testing()

set(lib_dir ${CMAKE_SOURCE_DIR}/lib)

# Cy static library.
add_library(cy STATIC ${CMAKE_SOURCE_DIR}/cy/cy.c)
target_include_directories(cy INTERFACE ${CMAKE_SOURCE_DIR}/cy)

# LibUDPard static library.
add_library(udpard STATIC ${lib_dir}/libudpard/libudpard/udpard.c)
target_compile_options(udpard PRIVATE -Wno-cast-align)
target_include_directories(udpard SYSTEM INTERFACE ${lib_dir}/libudpard/libudpard)

# UDP node example
add_executable(udp_node udp_node.c)
add_test(NAME run_udp_node COMMAND udp_node)
target_link_libraries(udp_node udpard cy)
