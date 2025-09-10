cmake_minimum_required(VERSION 3.24)
project(cy_wasm C)

# LibUDPard static library.
add_library(udpard STATIC ${CMAKE_SOURCE_DIR}/lib/libudpard/libudpard/udpard.c)
target_compile_options(udpard PRIVATE -Wno-cast-align -Wno-error)
target_include_directories(udpard SYSTEM INTERFACE ${CMAKE_SOURCE_DIR}/lib/libudpard/libudpard)

# Cy static library.
add_library(cy_wasm STATIC ${CMAKE_CURRENT_SOURCE_DIR}/cy_wasm.c)
target_link_libraries(cy_wasm PUBLIC cy udpard)
target_include_directories(cy_wasm SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
