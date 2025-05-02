/// Copyright (c) Pavel Kirienko

#pragma once

#include "udp.h"
#include <cy.h>
#include <udpard.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifndef __USE_POSIX199309
#define __USE_POSIX199309 // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
#endif
#include <time.h>

#define CY_UDP_IFACE_COUNT_MAX UDPARD_NETWORK_INTERFACE_COUNT_MAX

struct cy_udp_topic_t
{
    struct cy_topic_t           base;
    struct UdpardRxSubscription sub;
    UDPRxHandle                 sock_rx[CY_UDP_IFACE_COUNT_MAX];
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
        struct UdpardTx tx;
        UDPTxHandle     tx_sock;
        uint32_t        local_iface_address;
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

static inline uint64_t cy_udp_now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000U + (uint64_t)ts.tv_nsec / 1000U;
}

static inline void* _cy_udp_mem_alloc(void* const user, const size_t size)
{
    struct cy_udp_t* const cy_udp = (struct cy_udp_t*)user;
    void* const            out    = malloc(size);
    if (out != NULL) {
        cy_udp->diag.mem_allocated_bytes += size;
        cy_udp->diag.mem_allocated_fragments++;
    }
    return out;
}

static inline void _cy_udp_mem_free(void* const user, const size_t size, void* const pointer)
{
    struct cy_udp_t* const cy_udp = (struct cy_udp_t*)user;
    if (pointer != NULL) {
        assert(cy_udp->diag.mem_allocated_bytes >= size);
        assert(cy_udp->diag.mem_allocated_fragments > 0);
        cy_udp->diag.mem_allocated_bytes -= size;
        cy_udp->diag.mem_allocated_fragments--;
        free(pointer);
    }
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static inline uint64_t _cy_udp_now_us(struct cy_t* const cy)
{
    (void)cy;
    return cy_udp_now_us();
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static inline cy_err_t _cy_udp_transport_publish(struct cy_topic_t* const  topic,
                                                 const uint64_t            tx_deadline_us,
                                                 const struct cy_payload_t payload)
{
    struct cy_udp_t* const cy_udp = (struct cy_udp_t*)topic->cy;
    cy_err_t               res    = 0;
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
        if (cy_udp->io[i].tx.queue_capacity > 0) {
            const int32_t e = udpardTxPublish(&cy_udp->io[i].tx,
                                              tx_deadline_us,
                                              (enum UdpardPriority)topic->pub_priority,
                                              topic->subject_id,
                                              topic->pub_transfer_id,
                                              (struct UdpardPayload){ .size = payload.size, .data = payload.data },
                                              NULL);
            res             = (e < 0) ? (cy_err_t)e : ((res < 0) ? res : (cy_err_t)e);
        }
    }
    return res;
}

static inline bool _cy_udp_is_valid_ip(const uint32_t ip)
{
    return (ip > 0) && (ip < UINT32_MAX);
}

static inline cy_err_t _cy_udp_transport_subscribe(struct cy_topic_t* const cy_topic)
{
    struct cy_udp_topic_t* const cy_udp_topic = (struct cy_udp_topic_t*)cy_topic;
    const struct cy_udp_t* const cy_udp       = (struct cy_udp_t*)cy_topic->cy;

    // Set up the udpard subscription. This does not yet allocate any resources.
    cy_err_t res =
      udpardRxSubscriptionInit(&cy_udp_topic->sub, cy_topic->subject_id, cy_topic->sub_extent, cy_udp->rx_mem);
    if (res < 0) {
        return res; // No cleanup needed, no resources allocated yet.
    }

    // Open the sockets for this subscription.
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
        cy_udp_topic->sock_rx[i].fd = -1;
        if ((res >= 0) && _cy_udp_is_valid_ip(cy_udp->io[i].local_iface_address)) {
            res = (udpRxInit(&cy_udp_topic->sock_rx[i],
                             cy_udp->io[i].local_iface_address,
                             cy_udp_topic->sub.udp_ip_endpoint.ip_address,
                             cy_udp_topic->sub.udp_ip_endpoint.udp_port) < 0)
                    ? -1
                    : 0;
        }
    }

    // Cleanup on error.
    if (res < 0) {
        for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
            udpRxClose(&cy_udp_topic->sock_rx[i]);
        }
    }
    return res;
}

static inline void _cy_udp_transport_unsubscribe(struct cy_topic_t* const cy_topic)
{
    udpardRxSubscriptionFree(&((struct cy_udp_topic_t*)cy_topic)->sub);
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
        udpRxClose(&((struct cy_udp_topic_t*)cy_topic)->sock_rx[i]);
    }
}

/// Unused interfaces should have address either 0 or 0xFFFFFFFF.
static inline cy_err_t cy_udp_new(struct cy_udp_t* const cy_udp,
                                  const uint64_t         uid,
                                  const char* const      namespace_,
                                  const uint32_t         local_iface_address[CY_UDP_IFACE_COUNT_MAX],
                                  const size_t           tx_queue_capacity_per_iface,
                                  void* const            user)
{
    assert(cy_udp != NULL);
    memset(cy_udp, 0, sizeof(*cy_udp));
    // FIXME: the local node ID must be managed by the transport library. We should not touch that here.
    cy_udp->local_node_id = ((uint32_t)rand()) % UDPARD_NODE_ID_MAX;
    // Set up the memory resources. We could use block pool allocator here as well!
    cy_udp->mem.allocate                  = _cy_udp_mem_alloc;
    cy_udp->mem.deallocate                = _cy_udp_mem_free;
    cy_udp->mem.user_reference            = cy_udp;
    cy_udp->rx_mem.session                = cy_udp->mem;
    cy_udp->rx_mem.fragment               = cy_udp->mem;
    cy_udp->rx_mem.payload.deallocate     = _cy_udp_mem_free;
    cy_udp->rx_mem.payload.user_reference = cy_udp;

    // Initialize the udpard tx pipelines. They are all initialized always even if the corresponding iface is disabled,
    // for regularity, because an unused tx pipline needs no resources, so it's not a problem.
    cy_err_t res = 0;
    for (size_t i = 0; (i < CY_UDP_IFACE_COUNT_MAX) && (res >= 0); i++) {
        cy_udp->io[i].local_iface_address = 0;
        cy_udp->io[i].tx_sock.fd          = -1;
        res = udpardTxInit(&cy_udp->io[i].tx, &cy_udp->local_node_id, tx_queue_capacity_per_iface, cy_udp->mem);
    }
    if (res < 0) {
        return res; // Cleanup not required -- no resources allocated yet.
    }

    // Initialize the bottom layer first. Rx sockets are initialized per subscription, so not here.
    for (size_t i = 0; (i < CY_UDP_IFACE_COUNT_MAX) && (res >= 0); i++) {
        if (_cy_udp_is_valid_ip(local_iface_address[i])) {
            cy_udp->io[i].local_iface_address = local_iface_address[i];
            res = (udpTxInit(&cy_udp->io[i].tx_sock, local_iface_address[i]) < 0) ? -1 : 0;
        } else {
            cy_udp->io[i].tx.queue_capacity = 0;
        }
    }

    // Remember that cy_new may emit transfers, so we have to have the bottom part of the stack ready!
    // Cy is initialized in the last order.
    if (res >= 0) {
        res = cy_new(&cy_udp->base,
                     uid,
                     namespace_,
                     &cy_udp->heartbeat_topic.base,
                     &_cy_udp_now_us,
                     &_cy_udp_transport_publish,
                     &_cy_udp_transport_subscribe,
                     &_cy_udp_transport_unsubscribe,
                     user);
    }

    // Cleanup on error.
    if (res < 0) {
        for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
            struct UdpardTx* const     tx = &cy_udp->io[i].tx;
            const struct UdpardTxItem* it = NULL;
            while ((it = udpardTxPeek(tx))) {
                udpardTxFree(tx->memory, udpardTxPop(tx, it));
            }
            udpTxClose(&cy_udp->io[i].tx_sock); // The handle may be invalid, but we don't care.
        }
    }
    return res;
}

/// Write as many frames as possible from the tx queues to the network interfaces without blocking.
static inline void _cy_udp_tx_offload(struct cy_udp_t* const cy_udp)
{
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
        if (cy_udp->io[i].tx.queue_capacity > 0) {
            const struct UdpardTxItem* tqi    = udpardTxPeek(&cy_udp->io[i].tx);
            const uint64_t             now_us = cy_udp_now_us(); // Do not call it for every frame, it's costly.
            while (tqi != NULL) {
                // Attempt transmission only if the frame is not yet timed out while waiting in the TX queue.
                // Otherwise, just drop it and move on to the next one.
                if ((tqi->deadline_usec == 0) || (tqi->deadline_usec > now_us)) {
                    const int16_t send_res = udpTxSend(&cy_udp->io[i].tx_sock,
                                                       tqi->destination.ip_address,
                                                       tqi->destination.udp_port,
                                                       tqi->dscp,
                                                       tqi->datagram_payload.size,
                                                       tqi->datagram_payload.data);
                    if (send_res == 0) {
                        break; // Socket no longer writable, stop sending for now to retry later.
                    }
                    if (send_res < 0) {
                        cy_udp->diag.iface[i].tx_errors++;
                        cy_udp->diag.iface[i].tx_last_error = send_res;
                    }
                } else {
                    cy_udp->diag.iface[i].tx_timeouts++;
                }
                udpardTxFree(cy_udp->io[i].tx.memory, udpardTxPop(&cy_udp->io[i].tx, tqi));
                tqi = udpardTxPeek(&cy_udp->io[i].tx);
            }
        }
    }
}

/// If the deadline is not in the future, the function will process pending events once and return without blocking.
/// If the deadline is in the future and there are currently no events to process, the function will block until the
/// deadline is reached or until an event arrives. The function may return early even if no events are available.
/// The current monotonic time is as defined in cy_udp_now().
static inline cy_err_t cy_udp_spin_once(struct cy_udp_t* const cy_udp, const uint64_t deadline_us)
{
    // Process pending TX frames, if any.
    _cy_udp_tx_offload(cy_udp);

    // Fill out the TX awaitable array. May be empty if there's nothing to transmit at the moment.
    size_t         tx_count                         = 0;
    UDPTxAwaitable tx_await[CY_UDP_IFACE_COUNT_MAX] = { 0 };
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
        if (cy_udp->io[i].tx.queue_size > 0) { // There's something to transmit!
            tx_await[tx_count].handle = &cy_udp->io[i].tx_sock;
            tx_count++;
        }
    }

    // Fill out the RX awaitable array. The total number of RX sockets is the interface count times number of topics
    // we are subscribed to. Currently, we don't have a simple value that says how many topics we are subscribed to,
    // so we simply use the total number of topics; it's a bit wasteful but it's not a huge deal and we definitely
    // don't want to scan the topic index to count the ones we are subscribed to.
    const size_t   max_rx_count = CY_UDP_IFACE_COUNT_MAX * cy_udp->base.topic_count;
    size_t         rx_count     = 0;
    UDPRxAwaitable rx_await[max_rx_count];              // Initialization is not possible and is very wasteful anyway.
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) // Subscription sockets (one per topic per iface).
    {
        rx_await[rx_count].handle         = &app->sub_pnp_node_id_allocation.io[i];
        rx_await[rx_count].user_reference = &app->sub_pnp_node_id_allocation;
        rx_count++;
        assert(rx_count <= (sizeof(rx_await) / sizeof(rx_await[0])));
        // TODO: handle RPC as well!
    }

    cy_err_t res = 0;

    // While handling the events, we could have generated additional TX items, so we need to process them again.
    if (res >= 0) {
        _cy_udp_tx_offload(cy_udp);
    }
    return res;
}

static inline bool cy_udp_topic_new(struct cy_udp_t* const       cy_udp,
                                    struct cy_udp_topic_t* const topic,
                                    const char* const            name)
{
    return cy_topic_new(&cy_udp->base, &topic->base, name);
}

static inline cy_err_t cy_udp_subscribe(struct cy_udp_topic_t* const     topic,
                                        struct cy_subscription_t* const  sub,
                                        const size_t                     extent,
                                        const uint64_t                   transfer_id_timeout_us,
                                        const cy_subscription_callback_t callback)
{
    return cy_subscribe(&topic->base, sub, extent, transfer_id_timeout_us, callback);
}

static inline cy_err_t cy_udp_publish(struct cy_udp_topic_t* const topic,
                                      const uint64_t               tx_deadline_us,
                                      const struct cy_payload_t    payload)
{
    return _cy_udp_transport_publish(&topic->base, tx_deadline_us, payload);
}
