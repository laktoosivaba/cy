mkdir build
cd build
emmake cmake ..
emmake make clean && emmake make
#emcc cy_wasm/libcy_wasm.a cy/libcy.a -o /Users/andrey/Projects/rust/cy_rust/lib/libcy_wasm.wasm -sSTANDALONE_WASM --no-entry -sEXPORTED_FUNCTIONS=_cy_new_wasm,_malloc
emcc cy_wasm/libcy_wasm.a cy/libcy.a -o /Users/andrey/Projects/rust/cy_rust/lib/libcy_wasm.wasm -sSTANDALONE_WASM --no-entry -sEXPORTED_FUNCTIONS=_cy_wasm_new_main,_cy_wasm_spin_once,_malloc -sALLOW_TABLE_GROWTH
