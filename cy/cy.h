/// Copyright (c) Pavel Kirienko

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
#define CY_TOPIC_NAME_MAX 80

/// The max namespace length should also provide space for at least one separator and the one-character topic name.
#define CY_NAMESPACE_NAME_MAX (CY_TOPIC_NAME_MAX - 2)

/// If not sure, use this value for the transfer-ID timeout.
#define CY_TFER_ID_TIMEOUT_DEFAULT_us 2000000UL

/// The recommended minimum update interval.
#define CY_UPDATE_INTERVAL_MIN_us 200000UL

#define CY_TOPIC_TTL_DEFAULT_us (3600U * 1000000UL)

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
#define CY_ALLOC_SUBJECT_COUNT 6144
#define CY_TOTAL_SUBJECT_COUNT 8192

#define CY_SUBJECT_ID_INVALID 0xFFFFU

typedef int8_t cy_err_t;

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

struct cy_payload_mut_t
{
    size_t size;
    void*  data;
};

struct cy_tree_t
{
    struct cy_tree_t* up;
    struct cy_tree_t* lr[2];
    int8_t            bf;
};

struct cy_tfer_meta_t
{
    enum cy_prio_t priority;
    uint16_t       remote_node_id;
    uint64_t       tfer_id;
};

/// Returns the current monotonic time in microseconds.
typedef uint64_t (*cy_now_t)(struct cy_t*);

/// Instructs the underlying transport layer to publish a new message on the topic.
/// The function shall not increment the transfer-ID counter; Cy will do it.
typedef cy_err_t (*cy_transport_publish_t)(struct cy_topic_t*, uint64_t, struct cy_payload_t);

/// Instructs the underlying transport layer to create a new subscription on the topic.
typedef cy_err_t (*cy_transport_subscribe_t)(struct cy_topic_t*);

/// Instructs the underlying transport to destroy an existing subscription.
typedef cy_err_t (*cy_transport_unsubscribe_t)(struct cy_topic_t*);

/// Internal use only.
struct cy_crdt_meta_t
{
    uint64_t owner_uid;     ///< Zero is not a valid UID.
    uint32_t lamport_clock; ///< Starts at zero for an uninitialized entry.
};

struct cy_topic_t
{
    struct cy_tree_t index_hash;
    struct cy_tree_t index_subject_id;
    struct cy_tree_t index_gossip_time;

    struct cy_t* cy;

    /// The name is always null-terminated. We keep the size for convenience as well.
    size_t name_len;
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
    /// also, it ensures that the discriminator (hash >> 32) is zero, thus disabling its check.
    uint64_t hash;

    uint16_t subject_id;

    /// Updated with the current time when a gossip is either sent or received. Thus, this is the time when the
    /// network last saw the topic. It allows us to optimally decide which topic to gossip next such that redundant
    /// traffic is minimized and the time to full topic discovery is minimized.
    uint64_t last_gossip_us;

    /// True if the ID is assigned directly; e.g., "/7509".
    /// Pinned topics have zero discriminator for compatibility with old v1 nodes.
    bool pinned;

    struct cy_crdt_meta_t crdt_meta;

    /// The user can use this field for arbitrary purposes.
    void* user;

    /// Only used if the application publishes data on this topic.
    /// Hint: if the application needs to detect if a topic is published to, check tfer_id>0.
    /// The priority can be adjusted as needed by the user.
    uint64_t       pub_tfer_id;
    enum cy_prio_t pub_priority;

    /// Only used if the application subscribes on this topic.
    /// Hint: if the application needs to detect if a topic is subscribed to, check sub_list!=NULL.
    struct cy_sub_t* sub_list;
    uint64_t         sub_tfer_id_timeout_us;
    size_t           sub_extent;
    bool             sub_active;
};

typedef void (*cy_sub_callback_t)(struct cy_sub_t*, uint64_t, struct cy_tfer_meta_t, struct cy_payload_mut_t);
struct cy_sub_t
{
    struct cy_sub_t*   next;
    struct cy_topic_t* topic;
    cy_sub_callback_t  callback;
    void*              user;
};

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
    size_t namespace_len;
    char   namespace_[CY_NAMESPACE_NAME_MAX + 1];

    cy_now_t now;

    /// Transport layer interface functions.
    /// These can be underpinned by libcanard, libudpard, libserard, or any other transport library.
    cy_transport_publish_t     transport_publish;
    cy_transport_subscribe_t   transport_subscribe;
    cy_transport_unsubscribe_t transport_unsubscribe;

    uint64_t heartbeat_last_us;

    /// Topics needed by Cy itself.
    struct cy_topic_t heartbeat_topic;
    struct cy_sub_t   heartbeat_sub;

    /// All topics are indexed both by name and by subject-ID for fast lookups.
    struct cy_tree_t* topics_by_name;
    struct cy_tree_t* topics_by_subject_id;
    struct cy_tree_t* topics_by_gossip_time;

    /// This is to ensure we don't exhaust the subject-ID space.
    size_t topic_count;
};

/// The namespace may be NULL or empty, in which case it defaults to "~".
/// This function will never perform any network exchanges.
cy_err_t cy_new(struct cy_t* const               cy,
                const uint64_t                   uid,
                const char* const                namespace_,
                const cy_now_t                   now,
                const cy_transport_publish_t     publish,
                const cy_transport_subscribe_t   subscribe,
                const cy_transport_unsubscribe_t unsubscribe,
                void* const                      user,
                void* const                      heartbeat_topic_user);
void     cy_destroy(struct cy_t* const cy);

/// cy_update() shall be invoked whenever a new transfer is received; if no transfers are received in approx. 200
/// ms, the function must be invoked with null event. The invocation frequency SHALL NOT be lower than 1 Hz.
struct cy_update_event_t
{
    struct cy_topic_t*      topic; ///< Topic associated with the transport subscription by the lib*ards.
    uint64_t                ts_us;
    struct cy_tfer_meta_t   tfer;
    struct cy_payload_mut_t payload;
};
cy_err_t cy_update(struct cy_t* const cy, struct cy_update_event_t* const evt);

/// When the transport library detects a discriminator error, it will notify Cy about it to let it rectify the
/// problem. Transport frames with mismatched discriminators must be dropped; no processing at the transport layer
/// is needed. The function may emit one transfer; the result of the emission is returned. Transient errors can be
/// safely ignored.
///
/// If the transport library is unable to efficiently find the topic when a collision is found,
/// use cy_topic_find_by_subject_id().
/// The function has no effect if the topic is NULL; it is not an error to call it with NULL to simplify chaining
/// like:
///     cy_notify_discriminator_collision(cy_topic_find_by_subject_id(cy, collision_id));
cy_err_t cy_notify_discriminator_collision(struct cy_topic_t* topic);

/// Register a new topic that may be used by the local application for publishing, subscribing, or both.
/// Returns falsity if the topic name is not unique or not valid.
/// TODO: provide an option to restore a known subject-ID; e.g., loaded from non-volatile memory, to skip
/// allocation.
bool cy_topic_new(struct cy_t* const cy, struct cy_topic_t* const topic, const char* const name);
void cy_topic_destroy(struct cy_topic_t* const topic);

/// Complexity is logarithmic in the number of topics. NULL if not found.
struct cy_topic_t* cy_topic_find_by_name(struct cy_t* const cy, const char* const name);
struct cy_topic_t* cy_topic_find_by_subject_id(struct cy_t* const cy, uint16_t subject_id);

inline bool cy_topic_has_local_publishers(const struct cy_topic_t* const topic)
{
    return topic->pub_tfer_id > 0;
}

inline bool cy_topic_has_local_subscribers(const struct cy_topic_t* const topic)
{
    return topic->sub_list != NULL;
}

/// Topic discriminator is transmitted with every transport frame for subject-ID collision detection.
/// It is defined as the 32 most significant bits of the topic name hash, while the least significant bits are
/// used for deterministic subject-ID allocation. The two numbers must be uncorrelated to minimize collisions.
/// For pinned topics, the discriminator is zero because we don't want to check it for compatibility with old
/// nodes; this is ensured by our special topic hash function.
/// Transports are expected to use either the full 32-bit discriminator or any part thereof, depending on
/// their own design constraints.
inline uint32_t cy_topic_get_discriminator(const struct cy_topic_t* const topic)
{
    return (uint32_t)(topic->hash >> 32U);
}

/// Technically, the callback can be NULL, and the subscriber will work anyway.
/// One can still use the transfers from the underlying transport library before they are passed to cy_update().
///
/// Future expansion: add wildcard subscribers that match topic names by pattern. Requires unbounded dynamic memory.
///
/// Creation of a new subscription will involve network transactions unless the subject-ID is already known or is
/// fixed. However, the operation is non-blocking --- the message will be enqueued and sent in the background.
///
/// It is allowed to remove the subscription from its own callback, but not from the callback of another
/// subscription.
cy_err_t cy_subscribe(struct cy_topic_t* const topic,
                      struct cy_sub_t* const   sub,
                      const size_t             extent,
                      const uint64_t           tfer_id_timeout_us,
                      const cy_sub_callback_t  callback);
void     cy_unsubscribe(struct cy_topic_t* const topic, struct cy_sub_t* const sub);

cy_err_t cy_publish(struct cy_topic_t* const topic, const uint64_t tx_deadline_us, const struct cy_payload_t payload);

// TODO FIXME getters/setters for the user-modifiable and user-readable fields.

#ifdef __cplusplus
}
#endif
