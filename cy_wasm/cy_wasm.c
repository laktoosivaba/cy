// cy_wasm.c
#include "cy_wasm.h"

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((import_module("env"), import_name("wasm_now")))
extern cy_us_t wasm_now(void);

static cy_us_t platform_now(const cy_t* const cy)
{
    (void)cy;
    return wasm_now();
}

__attribute__((import_module("env"), import_name("wasm_realloc")))
extern void* wasm_realloc(void* ptr, size_t size);

static void* platform_realloc(cy_t* cy, void* ptr, size_t size)
{
    (void)cy;
    return wasm_realloc(ptr, size);
}

__attribute__((import_module("env"), import_name("wasm_prng")))
extern uint64_t wasm_prng(void);

static uint64_t platform_prng(const cy_t* const cy)
{
    (void)cy;
    return wasm_prng();
}

__attribute__((import_module("env"), import_name("wasm_buffer_release")))
extern void wasm_buffer_release(void* buffer);

static void platform_buffer_release(cy_t* cy, cy_buffer_owned_t buffer)
{
    (void)cy;
    wasm_buffer_release((void*)&buffer);
}

__attribute__((import_module("env"), import_name("wasm_node_id_set")))
extern cy_err_t wasm_node_id_set(void);

static cy_err_t platform_node_id_set(cy_t* cy)
{
    (void)cy;
    return wasm_node_id_set();
}

__attribute__((import_module("env"), import_name("wasm_node_id_clear")))
extern void wasm_node_id_clear(void);

static void platform_node_id_clear(cy_t* cy)
{
    (void)cy;
    wasm_node_id_clear();
}

// __attribute__((import_module("env"), import_name("wasm_node_id_bloom")))
// extern cy_bloom64_t* wasm_node_id_bloom(void);

// static cy_bloom64_t* platform_node_id_bloom(cy_t* cy)
// {
//     (void)cy;
//     return wasm_node_id_bloom();
// }
static cy_bloom64_t* platform_node_id_bloom(cy_t* const cy)
{
    assert(cy != NULL);
    cy_wasm_t* const cy_wasm = (cy_wasm_t*)cy;
    return &cy_wasm->node_id_bloom;
}

__attribute__((import_module("env"), import_name("wasm_p2p")))
extern cy_err_t wasm_p2p(uint16_t service_id, const cy_transfer_metadata_t* metadata, cy_us_t tx_deadline, void* payload);

static cy_err_t platform_p2p(cy_t* cy, uint16_t service_id, const cy_transfer_metadata_t metadata, cy_us_t tx_deadline, cy_buffer_borrowed_t payload)
{
    (void)cy;
    return wasm_p2p(service_id, &metadata, tx_deadline, (void*)&payload);
}

__attribute__((import_module("env"), import_name("wasm_topic_new")))
extern cy_topic_t* wasm_topic_new(void);

static cy_topic_t* platform_topic_new(cy_t* cy)
{
    (void)cy;
    return wasm_topic_new();
}

__attribute__((import_module("env"), import_name("wasm_topic_destroy")))
extern void wasm_topic_destroy(void* topic);

static void platform_topic_destroy(cy_t* cy, cy_topic_t* topic)
{
    (void)cy;
    wasm_topic_destroy(topic);
}

__attribute__((import_module("env"), import_name("wasm_topic_publish")))
extern cy_err_t wasm_topic_publish(void* pub, cy_us_t deadline, void* payload);

static cy_err_t platform_topic_publish(cy_t* cy, cy_publisher_t* pub, cy_us_t deadline, cy_buffer_borrowed_t payload)
{
    (void)cy;
    return wasm_topic_publish(pub, deadline, (void*)&payload);
}

__attribute__((import_module("env"), import_name("wasm_topic_subscribe")))
extern cy_err_t wasm_topic_subscribe(void* topic, void* params);

static cy_err_t platform_topic_subscribe(cy_t* cy, cy_topic_t* topic, cy_subscription_params_t params)
{
    (void)cy;
    return wasm_topic_subscribe(topic, &params);
}

__attribute__((import_module("env"), import_name("wasm_topic_unsubscribe")))
extern void wasm_topic_unsubscribe(void* topic);

static void platform_topic_unsubscribe(cy_t* cy, cy_topic_t* topic)
{
    (void)cy;
    wasm_topic_unsubscribe(topic);
}

__attribute__((import_module("env"), import_name("wasm_topic_advertise")))
extern void wasm_topic_advertise(void* topic, size_t response_extent_with_overhead);

static void platform_topic_advertise(cy_t* cy, cy_topic_t* topic, size_t response_extent_with_overhead)
{
    (void)cy;
    wasm_topic_advertise(topic, response_extent_with_overhead);
}

__attribute__((import_module("env"), import_name("wasm_topic_on_subscription_error")))
extern void wasm_topic_on_subscription_error(void* topic, cy_err_t error);

static void platform_topic_on_subscription_error(cy_t* cy, cy_topic_t* topic, const cy_err_t error)
{
    (void)cy;
    wasm_topic_on_subscription_error(topic, error);
}

static const cy_platform_t g_platform = {
    .now            = platform_now,
    .realloc        = platform_realloc,
    .prng           = platform_prng,
    .buffer_release = platform_buffer_release,

    .node_id_set   = platform_node_id_set,
    .node_id_clear = platform_node_id_clear,
    .node_id_bloom = platform_node_id_bloom,

    .p2p = platform_p2p,

    .topic_new                   = platform_topic_new,
    .topic_destroy               = platform_topic_destroy,
    .topic_publish               = platform_topic_publish,
    .topic_subscribe             = platform_topic_subscribe,
    .topic_unsubscribe           = platform_topic_unsubscribe,
    .topic_advertise             = platform_topic_advertise,
    .topic_on_subscription_error = platform_topic_on_subscription_error,

    .node_id_max      = 0xFFFE,
    .transfer_id_mask = UINT64_MAX,
};


void cy_new_wasm(const uint64_t uid, const uint16_t node_id, const char* namespace_str)
{

    printf("%llu\n", (unsigned long long)g_platform.now(NULL));

    cy_wasm_t* cy_wasm = (cy_wasm_t*)malloc(sizeof(cy_wasm_t));
    if (cy_wasm == NULL) {
        // Handle memory allocation failure
        fprintf(stderr, "Failed to allocate memory for instance\n");
        return;
    }

    cy_wasm->node_id_bloom.storage  = cy_wasm->node_id_bloom_storage;
    cy_wasm->node_id_bloom.n_bits   = sizeof(cy_wasm->node_id_bloom_storage) * CHAR_BIT;
    cy_wasm->node_id_bloom.popcount = 0;

    cy_err_t result = cy_new(&cy_wasm->base, &g_platform, uid, node_id, wkv_key(namespace_str));

    if (result != CY_OK) {
        // Return an instance with NULL platform to indicate failure
        memset(&cy_wasm, 0, sizeof(cy_wasm));
    }

    // return (void)instance;
}

void cy_destroy_wasm(cy_t instance)
{
    // Call the appropriate cleanup function from the library
    if (instance.platform != NULL) {
        // Assuming there's a cy_destroy function in the library
        cy_destroy(&instance);
    }
}
