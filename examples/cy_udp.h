/// Copyright (c) Pavel Kirienko

#pragma once

#include "udp.h"
#include <cy.h>
#include <udpard.h>

#define CY_UDP_IFACE_COUNT_MAX UDPARD_NETWORK_INTERFACE_COUNT_MAX

/// This is used to log and optionally report transient errors that are not fatal.
/// The occurrences count and the last_error are updated whenever an error is encountered internally.
struct cy_udp_err_handler_t
{
    uint64_t occurrences;
    cy_err_t last_error;
    void*    user; ///< Arbitrarily mutable by the user.
    /// The culprit points to the object that caused the error or is directly related to it.
    /// The callback may be NULL if error notifications are not needed.
    void (*callback)(struct cy_udp_err_handler_t* const self, void* const culprit);
};

struct cy_udp_topic_t
{
    struct cy_topic_t           base;
    struct UdpardRxSubscription sub;
    struct udp_rx_handle_t      sock_rx[CY_UDP_IFACE_COUNT_MAX];
    struct cy_udp_err_handler_t err_rx_transport;                    ///< Culprit points to this cy_udp_topic_t.
    struct cy_udp_err_handler_t err_rx_sock[CY_UDP_IFACE_COUNT_MAX]; ///< Culprit points to this cy_udp_topic_t.
};

struct cy_udp_t
{
    struct cy_t                    base;
    struct cy_udp_topic_t          heartbeat_topic;
    UdpardNodeID                   local_node_id;
    struct UdpardMemoryResource    mem;
    struct UdpardRxMemoryResources rx_mem;

    struct
    {
        struct UdpardTx             tx;
        struct udp_tx_handle_t      tx_sock;
        uint32_t                    local_iface_address;
        struct cy_udp_err_handler_t err_tx_sock; ///< Culprit points to this cy_udp_t.
        uint64_t                    tx_timeout_count;
    } io[CY_UDP_IFACE_COUNT_MAX];

    struct
    {
        size_t mem_allocated_fragments;
        size_t mem_allocated_bytes;
    } diag;
};

/// A convenience wrapper over clock_gettime(CLOCK_MONOTIC).
uint64_t cy_udp_now_us(void);

/// The namespace may be NULL or empty, in which case it defaults to "~".
///
/// Unused interfaces should have address either 0 or 0xFFFFFFFF;
/// to parse IP addresses from string see udp_parse_iface_address().
cy_err_t cy_udp_new(struct cy_udp_t* const cy_udp,
                    const uint64_t         uid,
                    const char* const      namespace_,
                    const uint32_t         local_iface_address[CY_UDP_IFACE_COUNT_MAX],
                    const size_t           tx_queue_capacity_per_iface);

/// Wait for events (blocking), process them, and return. Invoke this in a tight superloop to keep the system alive.
/// The function is guaranteed to return no later than in the heartbeat period, as configured in the Cy instance.
cy_err_t cy_udp_spin_once(struct cy_udp_t* const cy_udp);

/// Keep running the event loop until the deadline is reached or until the first error.
/// If the deadline is not in the future, the function will process pending events once and return without blocking.
/// If the deadline is in the future and there are currently no events to process, the function will block until the
/// deadline is reached or until an event arrives. The function may return early even if no events are available.
/// The current monotonic time is as defined in cy_udp_now().
cy_err_t cy_udp_spin_until(struct cy_udp_t* const cy_udp, const uint64_t deadline_us);

bool cy_udp_topic_new(struct cy_udp_t* const cy_udp, struct cy_udp_topic_t* const topic, const char* const name);

/// Trivial convenience wrapper over cy_subscribe().
static inline cy_err_t cy_udp_subscribe(struct cy_udp_topic_t* const     topic,
                                        struct cy_subscription_t* const  sub,
                                        const size_t                     extent,
                                        const uint64_t                   transfer_id_timeout_us,
                                        const cy_subscription_callback_t callback)
{
    return cy_subscribe(&topic->base, sub, extent, transfer_id_timeout_us, callback);
}

/// Trivial convenience wrapper over cy_publish().
static inline cy_err_t cy_udp_publish(struct cy_udp_topic_t* const topic,
                                      const uint64_t               tx_deadline_us,
                                      const struct cy_payload_t    payload)
{
    return cy_publish(&topic->base, tx_deadline_us, payload);
}
