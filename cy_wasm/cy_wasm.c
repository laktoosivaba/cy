// cy_wasm.c
#include "cy_wasm.h"
#include "cy_wasm_wit.h"

#include "wkv.h"
#include "libudpard/libudpard/udpard.h"

#include <assert.h>
#include <err.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void* platform_realloc(cy_t* const cy, void* const ptr, const size_t new_size)
{
    (void)cy;
    if (new_size > 0) {
        return realloc(ptr, new_size);
    }
    free(ptr);
    return NULL;
}

static void* mem_alloc(void* const user, const size_t size)
{
    cy_wasm_t* const cy_udp = (cy_wasm_t*)user;
    void* const           out    = malloc(size);
    if (size > 0) {
        if (out != NULL) {
            cy_udp->mem_allocated_fragments++;
        } else {
            cy_udp->mem_oom_count++;
        }
    }
    return out;
}

static void mem_free(void* const user, const size_t size, void* const pointer)
{
    cy_wasm_t* const cy_udp = (cy_wasm_t*)user;
    (void)size;
    if (pointer != NULL) {
        assert(cy_udp->mem_allocated_fragments > 0);
        cy_udp->mem_allocated_fragments--;
        memset(pointer, 0xA5, size); // a simple diagnostic aid
        free(pointer);
    }
}

__attribute__((import_module("env"), import_name("wasm_now"))) extern cy_us_t wasm_now(void);

static cy_us_t platform_now(const cy_t* const cy)
{
    (void)cy;
    return wasm_now();
}

__attribute__((import_module("env"), import_name("wasm_prng"))) extern uint64_t wasm_prng(void);

static uint64_t platform_prng(const cy_t* const cy)
{
    (void)cy;
    return wasm_prng();
}

__attribute__((import_module("env"), import_name("wasm_buffer_release"))) extern void wasm_buffer_release(void* buffer);
static void platform_buffer_release(cy_t* cy, cy_buffer_owned_t buffer)
{
    (void)cy;
    wasm_buffer_release((void*)&buffer);
}

__attribute__((import_module("env"), import_name("wasm_node_id_set"))) extern cy_err_t wasm_node_id_set(
  uint16_t node_id);

static cy_err_t platform_node_id_set(cy_t* cy)
{
    assert(cy != NULL);
    return wasm_node_id_set(cy->node_id);
}

__attribute__((import_module("env"), import_name("wasm_node_id_clear"))) extern void wasm_node_id_clear(void);

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

__attribute__((import_module("env"), import_name("wasm_p2p"))) extern cy_err_t
wasm_p2p(uint16_t service_id, const cy_transfer_metadata_t* metadata, cy_us_t tx_deadline, void* payload);

static cy_err_t platform_p2p(cy_t*                        cy,
                             uint16_t                     service_id,
                             const cy_transfer_metadata_t metadata,
                             cy_us_t                      tx_deadline,
                             cy_buffer_borrowed_t         payload)
{
    (void)cy;
    return wasm_p2p(service_id, &metadata, tx_deadline, (void*)&payload);
}

__attribute__((import_module("env"), import_name("wasm_topic_new"))) extern cy_topic_t* wasm_topic_new(
  cy_topic_t* cy_topic);

static cy_topic_t* platform_topic_new(cy_t* const cy)
{
    cy_wasm_topic_t* const topic = (cy_wasm_topic_t*)mem_alloc(cy, sizeof(cy_wasm_topic_t));
    if (topic != NULL) {
        memset(topic, 0, sizeof(cy_wasm_topic_t));
    }
    return wasm_topic_new((cy_topic_t*)topic);
}

__attribute__((import_module("env"), import_name("wasm_topic_destroy"))) extern void wasm_topic_destroy(void* topic);

static void platform_topic_destroy(cy_t* cy, cy_topic_t* topic)
{
    (void)cy;
    wasm_topic_destroy(topic);
}

__attribute__((import_module("env"), import_name("wasm_topic_publish"))) extern cy_err_t
wasm_topic_publish(void* pub, cy_us_t deadline, void* payload);

static cy_err_t platform_topic_publish(cy_t* cy, cy_publisher_t* pub, cy_us_t deadline, cy_buffer_borrowed_t payload)
{
    (void)cy;
    return wasm_topic_publish(pub, deadline, (void*)&payload);
}

__attribute__((import_module("env"), import_name("wasm_topic_subscribe"))) extern cy_err_t wasm_topic_subscribe(
  cy_topic_t* const              cy_topic,
  const cy_subscription_params_t params);

static cy_err_t platform_topic_subscribe(cy_t* const                    cy,
                                         cy_topic_t* const              cy_topic,
                                         const cy_subscription_params_t params)
{
    (void)cy;
    return wasm_topic_subscribe(cy_topic, params);
}

__attribute__((import_module("env"), import_name("wasm_topic_unsubscribe"))) extern void wasm_topic_unsubscribe(
  void* topic);

static void platform_topic_unsubscribe(cy_t* cy, cy_topic_t* topic)
{
    (void)cy;
    wasm_topic_unsubscribe(topic);
}

__attribute__((import_module("env"), import_name("wasm_topic_advertise"))) extern void wasm_topic_advertise(
  void*  topic,
  size_t response_extent_with_overhead);

static void platform_topic_advertise(cy_t* cy, cy_topic_t* topic, size_t response_extent_with_overhead)
{
    (void)cy;
    wasm_topic_advertise(topic, response_extent_with_overhead);
}

__attribute__((import_module("env"), import_name("wasm_topic_on_subscription_error"))) extern void
wasm_topic_on_subscription_error(void* topic, cy_err_t error);

static void platform_topic_on_subscription_error(cy_t* cy, cy_topic_t* topic, const cy_err_t error)
{
    (void)cy;
    wasm_topic_on_subscription_error(topic, error);
}

// __attribute__((import_module("env"), import_name("wasm_cy_trace")))
// extern void wasm_cy_trace(const char* message, i32 length);

void cy_trace(cy_t* const         cy,
              const char* const   file,
              const uint_fast16_t line,
              const char* const   func,
              const char* const   format,
              ...)
{
    (void)cy; // Suppress unused parameter warning

    // Handle the variadic arguments
    va_list args;
    va_start(args, format);

    // Print the formatted message
    vprintf(format, args);

    va_end(args);

    // Add a newline for better readability
    printf("\n");
}

static void default_tx_sock_err_handler(cy_wasm_t* const cy_wasm,
                                        const uint_fast8_t    iface_index,
                                        const uint32_t        err_no)
{
    CY_TRACE(&cy_wasm->base, "⚠️ TX socket error on iface #%u: %u", iface_index, (unsigned)err_no);
}

static void default_rpc_rx_sock_err_handler(cy_wasm_t* const cy_wasm,
                                            const uint_fast8_t    iface_index,
                                            const uint32_t        err_no)
{
    CY_TRACE(&cy_wasm->base, "⚠️ RPC RX socket error on iface #%u: %u", iface_index, (unsigned)err_no);
}

static void default_rx_sock_err_handler(cy_wasm_t* const       cy_wasm,
                                        cy_wasm_topic_t* const topic,
                                        const uint_fast8_t          iface_index,
                                        const uint32_t              err_no)
{
    CY_TRACE(
      &cy_wasm->base, "⚠️ RX socket error on iface #%u topic '%s': %u", iface_index, topic->base.name, (unsigned)err_no);
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

    .node_id_max      = UDPARD_NODE_ID_MAX,
    .transfer_id_mask = UINT64_MAX,
};

const char* namespace_str = "lala";

void on_file_read_msg(cy_t* const cy, const cy_arrival_t* const arv)
{
    (void)cy;
    (void)arv;
    // Implement your file read handling logic here
    // For example, you can read the requested file and send a response
}

cy_err_t cy_wasm_init(cy_wasm_t* const cy_wasm,
                          const uint64_t        uid)
{
    assert(cy_wasm != NULL);
    memset(cy_wasm, 0, sizeof(*cy_wasm));

    cy_wasm->response_extent_with_overhead = 64; // We start from an arbitrary value that just makes sense.
    cy_wasm->rpc_transfer_id_timeout       = CY_TRANSFER_ID_TIMEOUT_DEFAULT_us;
    // Set up the memory resources. We could use block pool allocator here as well!
    cy_wasm->mem.allocate                  = mem_alloc;
    cy_wasm->mem.deallocate                = mem_free;
    cy_wasm->mem.user_reference            = cy_wasm;
    cy_wasm->rx_mem.session                = cy_wasm->mem;
    cy_wasm->rx_mem.fragment               = cy_wasm->mem;
    cy_wasm->rx_mem.payload.deallocate     = mem_free;
    cy_wasm->rx_mem.payload.user_reference = cy_wasm;
    cy_wasm->rx_sock_err_handler           = default_rx_sock_err_handler;
    cy_wasm->tx_sock_err_handler           = default_tx_sock_err_handler;
    cy_wasm->rpc_rx_sock_err_handler       = default_rpc_rx_sock_err_handler;

    cy_wasm->node_id_bloom.storage  = cy_wasm->node_id_bloom_storage;
    cy_wasm->node_id_bloom.n_bits   = sizeof(cy_wasm->node_id_bloom_storage) * CHAR_BIT;
    cy_wasm->node_id_bloom.popcount = 0;

    cy_err_t res = CY_OK;

    printf("cy_wasm pointer: %p, size: %zu\n", (void*)cy_wasm, sizeof(*cy_wasm));
    printf("response_extent_with_overhead: %u\n", cy_wasm->response_extent_with_overhead);

    // if (res == CY_OK) {
        // res = cy_new(&cy_udp->base, &g_platform, uid, UDPARD_NODE_ID_UNSET, namespace_);
        // res = cy_new(&cy_wasm->base, &g_platform, uid, UDPARD_NODE_ID_UNSET, wkv_key(namespace_str));
    // }

    return res;
}

cy_err_t cy_wasm_new(cy_wasm_t* const cy_wasm,
                          const uint64_t        uid)
{
    assert(cy_wasm != NULL);

    printf("Architecture: %s-bit\n", (sizeof(void*) == 8) ? "64" : "32");

    printf("sizeof(response_extent_with_overhead): %zu\n", sizeof(cy_wasm->response_extent_with_overhead));
    printf("sizeof(rpc_transfer_id_timeout): %zu\n", sizeof(cy_wasm->rpc_transfer_id_timeout));
    printf("sizeof(mem): %zu\n", sizeof(cy_wasm->mem));
    printf("sizeof(rx_mem): %zu\n", sizeof(cy_wasm->rx_mem));
    printf("sizeof(rx_sock_err_handler): %zu\n", sizeof(cy_wasm->rx_sock_err_handler));
    printf("sizeof(tx_sock_err_handler): %zu\n", sizeof(cy_wasm->tx_sock_err_handler));
    printf("sizeof(rpc_rx_sock_err_handler): %zu\n", sizeof(cy_wasm->rpc_rx_sock_err_handler));
    printf("sizeof(node_id_bloom): %zu\n", sizeof(cy_wasm->node_id_bloom));
    printf("sizeof(node_id_bloom_storage): %zu\n", sizeof(cy_wasm->node_id_bloom_storage));
    printf("sizeof(local_iface_address): %zu\n", sizeof(cy_wasm->local_iface_address));
    printf("sizeof(base): %zu\n", sizeof(cy_wasm->base));

    printf("response_extent_with_overhead value: %u\n", cy_wasm->response_extent_with_overhead);
    printf("local_iface_address value: %u\n", cy_wasm->local_iface_address[0]);
    printf("node_id_bloom.popcount: %lu\n", cy_wasm->node_id_bloom.popcount);

    printf("cy_wasm pointer: %p, size: %zu\n", (void*)cy_wasm, sizeof(*cy_wasm));
    printf("mem.allocate: %p\n", (void*)cy_wasm->mem.allocate);
    printf("mem.deallocate: %p\n", (void*)cy_wasm->mem.deallocate);
    printf("mem.user_reference: %p\n", cy_wasm->mem.user_reference);

    cy_err_t res = CY_OK;

    if (res == CY_OK) {
        // res = cy_new(&cy_udp->base, &g_platform, uid, UDPARD_NODE_ID_UNSET, namespace_);
        res = cy_new(&cy_wasm->base, &g_platform, uid, UDPARD_NODE_ID_UNSET, wkv_key(namespace_str));
    }

    return res;
}
