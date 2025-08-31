cmake_minimum_required(VERSION 3.24)
project(cy_wasm C)

# Cy static library.
add_library(cy_wasm STATIC ${CMAKE_CURRENT_SOURCE_DIR}/cy_wasm.c)
target_link_libraries(cy_wasm PUBLIC cy)
target_include_directories(cy_wasm SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
