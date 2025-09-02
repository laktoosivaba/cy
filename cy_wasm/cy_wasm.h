// cy_wasm.h
#include "cy_platform.h"

#define CY_WASM_NODE_ID_BLOOM_64BIT_WORDS 128

typedef struct cy_wasm_t       cy_wasm_t;
typedef struct cy_wasm_topic_t cy_wasm_topic_t;

struct cy_wasm_topic_t
{
    cy_topic_t                  base;
};

struct cy_wasm_t
{
    cy_t base;

    uint64_t     node_id_bloom_storage[CY_WASM_NODE_ID_BLOOM_64BIT_WORDS];
    cy_bloom64_t node_id_bloom;

    size_t   mem_allocated_fragments;
    uint64_t mem_oom_count;
};

/**
 * Creates and initializes a new Cyphal instance with WebAssembly-friendly interface.
 * Returns the full structure by value instead of using pointers.
 *
 * @param platform Structure containing platform implementation functions
 * @param uid Node unique identifier
 * @param node_id Initial node ID or CY_NODE_ID_INVALID
 * @param namespace_str Namespace string
 * @return Initialized cy_t structure (platform field will be NULL if initialization failed)
 */
cy_err_t cy_wasm_new_main(const uint64_t uid, const uint16_t node_id);

/**
 * Properly destroys a Cyphal instance that was created with cy_new_wasm.
 *
 * @param instance The Cyphal instance to destroy
 */
void cy_destroy_wasm(cy_t instance);

cy_err_t cy_wasm_spin_once(cy_wasm_t* const cy_wasm);
