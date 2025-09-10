// cy_wasm.h
#pragma once

#include <cy_platform.h>
#include <udpard.h>
// #include <libudpard/libudpard/udpard.h>

#define CY_UDP_POSIX_IFACE_COUNT_MAX           4
#define CY_UDP_POSIX_NODE_ID_BLOOM_64BIT_WORDS 128

typedef struct udp_wrapper_tx_t udp_wrapper_tx_t;
typedef struct udp_wrapper_rx_t udp_wrapper_rx_t;

typedef struct cy_wasm_t       cy_wasm_t;
typedef struct cy_wasm_topic_t cy_wasm_topic_t;

/// These definitions are highly platform-specific.
/// Note that LibUDPard does not require the same socket to be usable for both transmission and reception.
struct udp_wrapper_tx_t
{
    int fd;
};
struct udp_wrapper_rx_t
{
    int fd;
    // dgram accepted if iface index matches AND (src adr OR src port differ). The latter is to discard own traffic.
    uint32_t allow_iface_index;
    uint32_t deny_source_address;
    uint16_t deny_source_port;
};

struct cy_wasm_topic_t
{
    cy_topic_t                  base;
    struct UdpardRxSubscription sub;
    udp_wrapper_rx_t            sock_rx[CY_UDP_POSIX_IFACE_COUNT_MAX];

    /// The count of out-of-memory errors that occurred while processing this topic.
    /// Every OOM implies that either a frame or a full transfer were lost.
    uint64_t rx_oom_count;

    /// Initialized from the eponymous field of cy_udp_posix_t when a new topic is created.
    void (*rx_sock_err_handler)(cy_wasm_t*       cy_udp,
                                cy_wasm_topic_t* topic,
                                uint_fast8_t          iface_index,
                                uint32_t              err_no);
};

struct cy_wasm_t
{
    cy_t base;

    /// Maximum seen value across all topics since initialization.
    size_t response_extent_with_overhead;

    /// This can be overridden immediately after initialization if necessary.
    /// Changing this after the node-ID is allocated may not have any effect.
    cy_us_t rpc_transfer_id_timeout;

    uint64_t     node_id_bloom_storage[CY_UDP_POSIX_NODE_ID_BLOOM_64BIT_WORDS];
    cy_bloom64_t node_id_bloom;

    struct UdpardMemoryResource    mem;
    struct UdpardRxMemoryResources rx_mem;

    struct UdpardRxRPCDispatcher rpc_rx_dispatcher;
    struct UdpardRxRPCPort       rpc_rx_port_topic_response;

    uint32_t local_iface_address[CY_UDP_POSIX_IFACE_COUNT_MAX];

    struct
    {
        struct UdpardTx  udpard_tx;
        udp_wrapper_tx_t sock;
        uint16_t         local_port;
        uint64_t         frames_expired; ///< Number of tx frames that have timed out while waiting in the queue.
    } tx[CY_UDP_POSIX_IFACE_COUNT_MAX];

    struct
    {
        udp_wrapper_rx_t sock;
        /// The count of out-of-memory errors that occurred while reading from this socket.
        /// Every OOM implies that either a frame or a full transfer were lost.
        uint64_t oom_count;
    } rpc_rx[CY_UDP_POSIX_IFACE_COUNT_MAX];

    /// Handler for errors occurring while reading from the socket of the topic on the specified iface.
    /// The default handler is provided which will use CY_TRACE() to report the error.
    /// This is only used to initialize the corresponding field of cy_udp_posix_topic_t when a new topic is created.
    /// Changes to this handler will not affect existing topics.
    void (*rx_sock_err_handler)(cy_wasm_t*       cy_wasm,
                                cy_wasm_topic_t* topic,
                                uint_fast8_t          iface_index,
                                uint32_t              err_no);

    /// Handler for errors occurring while writing into a tx socket on the specified iface.
    /// These are platform-specific.
    /// The default handler is provided which will use CY_TRACE() to report the error.
    void (*tx_sock_err_handler)(cy_wasm_t* cy_wasm, uint_fast8_t iface_index, uint32_t err_no);

    /// Handler for errors occurring while reading from an RPC RX socket on the specified iface.
    /// These are platform-specific.
    /// The default handler is provided which will use CY_TRACE() to report the error.
    void (*rpc_rx_sock_err_handler)(cy_wasm_t* topic, uint_fast8_t iface_index, uint32_t err_no);

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
cy_err_t               cy_wasm_new(cy_wasm_t* const cy_wasm,
                                        const uint64_t        uid,
                                        const uint32_t        local_iface_address[CY_UDP_POSIX_IFACE_COUNT_MAX],
                                        const size_t          tx_queue_capacity_per_iface);

