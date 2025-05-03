/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/// A sensible middle ground between worst-case gossip traffic and memory utilization vs. longest name support.
/// In CAN FD networks, topic names should not be longer than 22 bytes to avoid multi-frame heartbeats.
///
/// The name length is chosen such that together with the 1-byte length prefix the result is a multiple of 8 bytes,
/// because it helps with memory-aliased C structures for quick serialization.
#define CY_TOPIC_NAME_MAX 103

/// The max namespace length should also provide space for at least one separator and the one-character topic name.
#define CY_NAMESPACE_NAME_MAX (CY_TOPIC_NAME_MAX - 2)

/// If not sure, use this value for the transfer-ID timeout.
#define CY_TRANSFER_ID_TIMEOUT_DEFAULT_us 2000000UL

/// The rate at which the heartbeat topic is published is also the absolute minimum library state update interval.
/// It is not an error to update it more often, and in fact it is desirable to reduce possible frequency aliasing.
#define CY_HEARTBEAT_PERIOD_DEFAULT_us 100000UL

/// The range of unregulated identifiers to use for CRDT topic allocation.
/// The range should be the same for all applications, so that they can all make deterministic and identical
/// subject-ID allocations even when the network is partitioned. This is not strictly necessary, but it reduces the
/// likelihood of collisions and the duration of temporary service disruptions when the network is healing after
/// de-partitioning. The range should also be as large as possible for the same reason.
///
/// Fixed topics (such as the old v1 topics with manually assigned IDs) should not be allocated in the CRDT range,
/// because old v1 nodes to not participate in the CRDT gossip, and are unable to alert the network about conflicts.
/// This problem could be addressed by the occupancy mask, but it has downsides of its own (does not allow freeing
/// topics, needs 768 bytes of memory), so we prefer a simpler solution of having to force static topics into the
/// higher ID range.
#define CY_TOPIC_SUBJECT_COUNT 6144
#define CY_SUBJECT_BITS        13U
#define CY_TOTAL_SUBJECT_COUNT (1UL << CY_SUBJECT_BITS)

#define CY_SUBJECT_ID_INVALID 0xFFFFU

typedef int32_t cy_err_t;

struct cy_t;
struct cy_topic_t;

enum cy_prio_t
{
    cy_prio_exceptional = 0,
    cy_prio_immediate   = 1,
    cy_prio_fast        = 2,
    cy_prio_high        = 3,
    cy_prio_nominal     = 4,
    cy_prio_low         = 5,
    cy_prio_slow        = 6,
    cy_prio_optional    = 7,
};

struct cy_payload_t
{
    size_t      size;
    const void* data;
};

struct cy_tree_t
{
    struct cy_tree_t* up;
    struct cy_tree_t* lr[2];
    int8_t            bf;
};

struct cy_transfer_meta_t
{
    enum cy_prio_t priority;
    uint16_t       remote_node_id;
    uint64_t       transfer_id;
};

/// Returns the current monotonic time in microseconds. The initial time may be arbitrary (doesn't have to be zero).
/// The returned value may be zero initially, but all subsequent calls must return strictly positive values.
typedef uint64_t (*cy_now_t)(struct cy_t*);

/// Instructs the underlying transport layer to publish a new message on the topic.
/// The function shall not increment the transfer-ID counter; Cy will do it.
typedef cy_err_t (*cy_transport_publish_t)(struct cy_topic_t*, uint64_t, struct cy_payload_t);

/// Instructs the underlying transport layer to create a new subscription on the topic.
typedef cy_err_t (*cy_transport_subscribe_t)(struct cy_topic_t*);

/// Instructs the underlying transport to destroy an existing subscription.
typedef void (*cy_transport_unsubscribe_t)(struct cy_topic_t*);

struct cy_topic_t
{
    struct cy_tree_t index_hash; ///< Hash index handle MUST be the first field.
    struct cy_tree_t index_subject_id;
    struct cy_tree_t index_gossip_time;

    struct cy_t* cy;

    /// The name is always null-terminated. We keep the size for convenience as well.
    size_t name_length;
    char   name[CY_TOPIC_NAME_MAX + 1];

    /// Assuming we have 1000 topics, the probability of a topic name hash collision is:
    /// >>> from decimal import Decimal
    /// >>> n = 1000
    /// >>> d = Decimal(2**64)
    /// >>> 1 - ((d-1)/d) ** ((n*(n-1))//2)
    /// About 2.7e-14, or one in 37 trillion.
    ///
    /// For pinned topics, the name hash equals the subject-ID.
    /// This ensures that the preferred subject-ID is still found using (hash % CY_ALLOC_SUBJECT_COUNT);
    /// also, it ensures that the discriminator (hash >> CY_SUBJECT_BITS) is zero, thus disabling its check.
    uint64_t hash;
    uint64_t lamport_clock;
    uint64_t owner_uid; ///< Zero is not a valid UID.
    uint16_t subject_id;

    /// Updated whenever the topic is gossiped or its gossip is received from another node.
    /// It allows us to optimally decide which topic to gossip next such that redundant traffic and the time to
    /// full network state discovery is minimized.
    ///
    /// TODO: consider this: what if the network is semi-partitioned where some nodes see a subset of others,
    /// and our node straddles multiple partitions? This could occur in packet switched networks or if redundant
    /// interfaces are used. Our coordinated publishing can naturally settle on a stable state where some nodes
    /// become responsible for publishing specific topics, and nodes that happen to be in a different partition
    /// will never see those topics. Do we care about this failure case? What needs analysis is how likely it
    /// is for a set of nodes to encounter a stable arrangement where each node publishes only a subset of topics.
    uint64_t last_gossip_us;

    /// The user can use this field for arbitrary purposes.
    void* user;

    /// Only used if the application publishes data on this topic.
    /// The priority can be adjusted as needed by the user.
    uint64_t       pub_transfer_id;
    enum cy_prio_t pub_priority;

    /// Only used if the application subscribes on this topic.
    struct cy_subscription_t* sub_list;
    uint64_t                  sub_transfer_id_timeout_us;
    size_t                    sub_extent;
    bool                      sub_active;
};

typedef void (*cy_subscription_callback_t)(struct cy_subscription_t* subscription,
                                           uint64_t                  timestamp_us,
                                           struct cy_transfer_meta_t metadata,
                                           struct cy_payload_t       payload);
struct cy_subscription_t
{
    struct cy_subscription_t*  next;
    struct cy_topic_t*         topic;
    cy_subscription_callback_t callback; ///< Maybe NULL; may be changed at any time (e.g. to implement FSM).
    void*                      user;
};

/// There are only two functions whose invocations may result in network traffic:
/// - cy_heartbeat() -- heartbeat only, at most one per call (for default rate see CY_HEARTBEAT_PERIOD_DEFAULT_us).
/// - cy_publish()   -- user transfers only.
struct cy_t
{
    /// The UID is actually composed of 16-bit vendor-ID, 16-bit product-ID, and 32-bit instance-ID (aka serial
    /// number), arranged from the most significant to the least significant bits. However, Cy doesn't care about
    /// the inner structure of the UID; all it needs is a number to order the nodes on the network.
    /// Zero is not a valid UID.
    uint64_t uid;

    uint64_t started_at_us;

    /// The user can use this field for arbitrary purposes.
    void* user;

    /// Namespace prefix added to all topics created on this instance, unless the topic name starts with "/".
    size_t namespace_length;
    char   namespace_[CY_NAMESPACE_NAME_MAX + 1];

    cy_now_t now;

    /// Transport layer interface functions.
    /// These can be underpinned by libcanard, libudpard, libserard, or any other transport library.
    cy_transport_publish_t     transport_publish;
    cy_transport_subscribe_t   transport_subscribe;
    cy_transport_unsubscribe_t transport_unsubscribe;

    /// Heartbeat topic and related items.
    struct cy_topic_t*       heartbeat_topic;
    struct cy_subscription_t heartbeat_sub;
    uint64_t                 heartbeat_next_us;
    uint64_t                 heartbeat_period_us; ///< Can be adjusted by the user. Prefer larger period on CAN.

    /// Topics have multiple indexes.
    struct cy_tree_t* topics_by_hash;
    struct cy_tree_t* topics_by_subject_id;
    struct cy_tree_t* topics_by_gossip_time;

    /// This is to ensure we don't exhaust the subject-ID space.
    size_t topic_count;
};

/// The namespace may be NULL or empty, in which case it defaults to "~".
///
/// The heartbeat_topic must point to an uninitialized topic structure that will be used to publish heartbeat messages;
/// this is the only topic that is needed by Cy itself. It will be initialized and managed automatically; if necessary,
/// the user can add additional subscriptions to it later.
///
/// No network traffic will be generated. The only function that can send heartbeat messages is cy_heartbeat().
cy_err_t cy_new(struct cy_t* const               cy,
                const uint64_t                   uid,
                const char* const                namespace_,
                struct cy_topic_t* const         heartbeat_topic,
                const cy_now_t                   now,
                const cy_transport_publish_t     publish,
                const cy_transport_subscribe_t   subscribe,
                const cy_transport_unsubscribe_t unsubscribe);
void     cy_destroy(struct cy_t* const cy);

/// This is invoked whenever a new transfer on the topic is received.
/// The library will dispatch it to the appropriate subscriber callbacks.
/// Excluding the callbacks, the time complexity is constant.
///
/// If this is invoked together with cy_heartbeat(), then cy_ingest() must be invoked BEFORE cy_heartbeat()
/// to ensure that the latest state updates are reflected in the next heartbeat message.
void cy_ingest(struct cy_topic_t* const        topic,
               const uint64_t                  timestamp_us,
               const struct cy_transfer_meta_t metadata,
               const struct cy_payload_t       payload);

/// This function must be invoked periodically to let the library publish heartbeats.
/// The invocation period MUST NOT EXCEED the heartbeat period configured in cy_t; there is no lower limit.
/// To avoid frequency aliasing, one may prefer to invoke it at any higher rate; a few ms is good.
///
/// This is the only function that generates heartbeat --- the only kind of auxiliary traffic needed to support
/// named topics. The returned value indicates the success of the heartbeat publication, if any took place, or zero.
///
/// If this is invoked together with cy_ingest(), then cy_heartbeat() must be invoked AFTER cy_ingest() to ensure
/// that the latest state updates are reflected in the heartbeat message.
///
/// Excluding the transport_publish dependency, the time complexity is logarithmic in the number of topics.
cy_err_t cy_heartbeat(struct cy_t* const cy);

/// When the transport library detects a discriminator error, it will notify Cy about it to let it rectify the
/// problem. Transport frames with mismatched discriminators must be dropped; no processing at the transport layer
/// is needed. This function is not essential for the protocol to function, but it speeds up collision repair.
///
/// The function will not perform any IO and will return immediately after quickly updating an internal state.
/// It is thus safe to invoke it from a deep callback or from deep inside the transport library; the side effects
/// are confined to the Cy state only. The time complexity is logarithmic in the number of topics.
///
/// If the transport library is unable to efficiently find the topic when a collision is found, use
/// cy_topic_find_by_subject_id(). The function has no effect if the topic is NULL; it is not an error to call it
/// with NULL to simplify chaining like:
///     cy_notify_discriminator_collision(cy_topic_find_by_subject_id(cy, collision_subject_id));
void cy_notify_discriminator_collision(struct cy_topic_t* const topic);

/// Register a new topic that may be used by the local application for publishing, subscribing, or both.
/// Returns falsity if the topic name is not unique or not valid.
/// Pinned topics should not use subject-IDs below CY_ALLOC_SUBJECT_COUNT because the network may have to move them.
/// No network traffic is generated here.
/// TODO: provide an option to restore a known subject-ID; e.g., loaded from non-volatile memory, to skip allocation.
bool cy_topic_new(struct cy_t* const cy, struct cy_topic_t* const topic, const char* const name);
void cy_topic_destroy(struct cy_topic_t* const topic);

/// Complexity is logarithmic in the number of topics. NULL if not found.
struct cy_topic_t* cy_topic_find_by_name(struct cy_t* const cy, const char* const name);
struct cy_topic_t* cy_topic_find_by_subject_id(struct cy_t* const cy, uint16_t subject_id);

/// Iterate over all topics in arbitrary order.
/// This is useful when handling IO multiplexing (building the list of descriptors to read) and for introspection.
/// The function does nothing if the cy or callback are NULL.
void cy_topic_for_each(struct cy_t* const cy,
                       void (*callback)(struct cy_topic_t* const topic, void* const user),
                       void* const user);

static inline bool cy_topic_has_local_publishers(const struct cy_topic_t* const topic)
{
    return topic->pub_transfer_id > 0;
}

static inline bool cy_topic_has_local_subscribers(const struct cy_topic_t* const topic)
{
    return topic->sub_list != NULL;
}

/// Topic discriminator is fused into every transport frame and possibly transfer for subject-ID collision detection.
/// It is defined as the 51 most significant bits of the topic name hash, while the least significant bits are
/// used for deterministic subject-ID allocation. The two numbers must be uncorrelated to minimize collisions.
/// For pinned topics, the discriminator is zero because we don't want to check it for compatibility with old
/// nodes; this is ensured by our special topic hash function. Transports are expected to use either the full 51-bit
/// discriminator or any part thereof (excepting the most significant zero bits ofc), depending on their design.
///
/// Given the size of the subject-ID space of 6144 identifiers and 2^51 possible discriminators, the probability of
/// a collision on a network with 1000 topics is birthday(6144*(2**51), 1000) ~ 3.6e-14, or one in ~28 trillion.
/// This is assuming that all bits of the discriminator are used. If only 32 bits are used, the probability is
/// birthday(6144*(2**32), 1000) ~ 1.9e-8, or one in 53 million.
static inline uint64_t cy_topic_get_discriminator(const struct cy_topic_t* const topic)
{
    return topic->hash >> CY_SUBJECT_BITS;
}

/// Technically, the callback can be NULL, and the subscriber will work anyway.
/// One can still use the transfers from the underlying transport library before they are passed to cy_ingest().
///
/// Future expansion: add wildcard subscribers that match topic names by pattern. Requires unbounded dynamic memory.
///
/// Creation of a new subscription will involve network transactions unless the subject-ID is already known or is
/// fixed. However, the operation is non-blocking --- the message will be enqueued and sent in the background.
///
/// It is allowed to remove the subscription from its own callback, but not from the callback of another
/// subscription.
cy_err_t cy_subscribe(struct cy_topic_t* const         topic,
                      struct cy_subscription_t* const  sub,
                      const size_t                     extent,
                      const uint64_t                   transfer_id_timeout_us,
                      const cy_subscription_callback_t callback);
void     cy_unsubscribe(struct cy_topic_t* const topic, struct cy_subscription_t* const sub);

/// The transfer-ID is always incremented, even on failure, to signal lost messages.
/// Therefore, the transfer-ID is effectively the number of times this function was called on the topic.
/// This function always publishes only one transfer as requested; no auxiliary traffic is generated.
cy_err_t cy_publish(struct cy_topic_t* const topic, const uint64_t tx_deadline_us, const struct cy_payload_t payload);

/// Make topic name canonical. The input buffer will be modified in place.
/// The result is guaranteed to be not longer than the original name.
/// Returns true on success, false if the name is not valid.
/// Example: "/foo//bar/" -> "/foo/bar"
bool cy_canonicalize(char* const topic_name);

#ifdef __cplusplus
}
#endif
