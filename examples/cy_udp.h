/// Copyright (c) Pavel Kirienko

#pragma once

#include "udp.h"
#include <cy.h>
#include <udpard.h>

#define CY_UDP_IFACE_COUNT_MAX           UDPARD_NETWORK_INTERFACE_COUNT_MAX
#define CY_UDP_SPIN_ONCE_MAX_DURATION_us CY_UPDATE_INTERVAL_MIN_us

struct cy_udp_topic_t
{
    struct cy_topic_t           base;
    struct UdpardRxSubscription sub;
    struct udp_rx_handle_t      sock_rx[CY_UDP_IFACE_COUNT_MAX];

    struct
    {
        uint64_t    udpard_rx_errors;
        int_fast8_t udpard_rx_last_error;
        struct
        {
            uint64_t rx_errors;
            int16_t  rx_last_error;
        } iface[CY_UDP_IFACE_COUNT_MAX];
    } diag;
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
        struct UdpardTx        tx;
        struct udp_tx_handle_t tx_sock;
        uint32_t               local_iface_address;
    } io[CY_UDP_IFACE_COUNT_MAX];

    struct
    {
        size_t mem_allocated_fragments;
        size_t mem_allocated_bytes;
        struct
        {
            uint64_t tx_errors;
            uint64_t tx_timeouts;
            int16_t  tx_last_error;
        } iface[CY_UDP_IFACE_COUNT_MAX];
    } diag;
};

/// A convenience wrapper over clock_gettime(CLOCK_MONOTIC).
uint64_t cy_udp_now_us(void);

/// The namespace may be NULL or empty, in which case it defaults to "~".
/// Unused interfaces should have address either 0 or 0xFFFFFFFF.
cy_err_t cy_udp_new(struct cy_udp_t* const cy_udp,
                    const uint64_t         uid,
                    const char* const      namespace_,
                    const uint32_t         local_iface_address[CY_UDP_IFACE_COUNT_MAX],
                    const size_t           tx_queue_capacity_per_iface,
                    void* const            user);

/// Wait for events (blocking), process them, and return. Invoke this in a tight superloop to keep the system alive.
/// The function is guaranteed to return no later than in CY_UDP_SPIN_ONCE_MAX_DURATION_us.
cy_err_t cy_udp_spin_once(struct cy_udp_t* const cy_udp);

/// Keep running the event loop until the deadline is reached or until the first error.
/// If the deadline is not in the future, the function will process pending events once and return without blocking.
/// If the deadline is in the future and there are currently no events to process, the function will block until the
/// deadline is reached or until an event arrives. The function may return early even if no events are available.
/// The current monotonic time is as defined in cy_udp_now().
cy_err_t cy_udp_spin_until(struct cy_udp_t* const cy_udp, const uint64_t deadline_us);

/// Trivial convenience wrapper over cy_topic_new().
static inline bool cy_udp_topic_new(struct cy_udp_t* const       cy_udp,
                                    struct cy_udp_topic_t* const topic,
                                    const char* const            name)
{
    return cy_topic_new(&cy_udp->base, &topic->base, name);
}

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
