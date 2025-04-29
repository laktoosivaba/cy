/// Copyright (c) Pavel Kirienko

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/// A sensible middle ground between worst-case gossip traffic and memory utilization vs. longest name support.
#define CY_TOPIC_NAME_MAX 80

/// If not sure, use this value for the transfer-ID timeout.
#define CY_TFER_ID_TIMEOUT_DEFAULT_us 2000000UL

/// The recommended minimum update interval.
#define CY_UPDATE_INTERVAL_MIN_us 200000UL

#define CY_TOPIC_TTL_DEFAULT_us (3600U * 1000000UL)

/// The range of unregulated identifiers to use for CRDT topic allocation.
/// The range should be the same for all applications, so that they can all make deterministic and identical
/// subject-ID allocations even when the network is partitioned.
/// Larger ranges are preferable because they reduce the probability of collisions, and thus the probability
/// and duration of temporary service disruptions when the network is healing after de-partitioning.
#define CY_CRDT_SUBJECT_COUNT 6144
#define CY_TOTAL_SUBJECT_COUNT 8192

#define CY_SUBJECT_ID_INVALID 0xFFFFU

#define CY_SUBJECT_OCCUPANCY_MASK_SIZE_BYTES ((CY_CRDT_SUBJECT_COUNT + 7) / 8)

typedef int8_t cy_err_t;

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
typedef cy_err_t (*cy_transport_publish_t)(struct cy_t*, struct cy_topic_t*, uint64_t, struct cy_payload_t);

/// Instructs the underlying transport layer to create a new subscription on the topic.
/// This function is only invoked when the specific subject-ID is already established, meaning
/// that the corresponding field in the topic struct is valid.
typedef cy_err_t (*cy_transport_subscribe_t)(struct cy_t*, struct cy_topic_t*);

/// Instructs the underlying transport to destroy an existing subscription.
typedef cy_err_t (*cy_transport_unsubscribe_t)(struct cy_t*, struct cy_topic_t*);

/// Internal use only.
struct cy_crdt_meta_t
{
    uint64_t owner_uid;      ///< Zero is not a valid UID.
    uint32_t lamport_clock;  ///< Starts at zero for an uninitialized entry.
};

struct cy_topic_t
{
    struct cy_tree_t index_name;
    struct cy_tree_t index_subject_id;

    const char* name;
    uint64_t    name_hash;
    uint16_t    name_crc;

    uint16_t subject_id;
    bool     fixed;  ///< True if the ID is assigned directly; e.g., "/7509".

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

struct cy_sub_event_t
{
    struct cy_t*            cy;
    struct cy_topic_t*      topic;
    struct cy_sub_t*        sub;
    uint64_t                ts_us;
    struct cy_tfer_meta_t   tfer;
    struct cy_payload_mut_t payload;
};

struct cy_sub_t
{
    struct cy_sub_t* next;
    void (*callback)(const struct cy_sub_event_t*);
    void* user;
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

    uint8_t subject_occupancy_mask[CY_SUBJECT_OCCUPANCY_MASK_SIZE_BYTES];

    /// Returns the current monotonic time in microseconds.
    cy_now_t now;

    /// Transport layer interface functions.
    /// These can be underpinned by libcanard, libudpard, libserard, or any other transport library.
    cy_transport_publish_t     transport_publish;
    cy_transport_subscribe_t   transport_subscribe;
    cy_transport_unsubscribe_t transport_unsubscribe;

    /// Topics needed by Cy itself.
    struct cy_topic_t heartbeat_topic;
    struct cy_sub_t   heartbeat_sub;

    /// All topics are indexed both by name and by subject-ID for fast lookups.
    struct cy_tree_t* topics_by_name;
    struct cy_tree_t* topics_by_subject_id;
};

struct cy_update_event_t
{
    struct cy_topic_t*      topic;
    uint64_t                ts_us;
    struct cy_tfer_meta_t   tfer;
    uint16_t                topic_crc;
    struct cy_payload_mut_t payload;
};

cy_err_t cy_new(struct cy_t* const               cy,
                const uint64_t                   uid,
                void* const                      user,
                const cy_now_t                   now,
                const cy_transport_publish_t     publish,
                const cy_transport_subscribe_t   subscribe,
                const cy_transport_unsubscribe_t unsubscribe,
                void* const                      heartbeat_topic_user);
void     cy_del(struct cy_t* const cy);

/// This function shall be invoked whenever a new transfer is received;
/// if no transfers are received in approx. 200 ms, the function must be invoked with NULL topic and transfer.
/// The invocation frequency SHALL NOT be lower than 1 Hz.
cy_err_t cy_update(struct cy_t* const              cy,  //
                   struct cy_update_event_t* const evt);

/// Register a new topic that may be used by the local application for publishing, subscribing, or both.
/// Returns falsity if the topic name is not unique or not valid.
bool cy_topic_new(struct cy_t* const       cy,  //
                  struct cy_topic_t* const topic,
                  const char* const        topic_name);
void cy_topic_del(struct cy_t* const       cy,  //
                  struct cy_topic_t* const topic);

/// Technically, the callback can be NULL, and the subscriber will work anyway.
/// One can still use the transfers from the underlying transport library before they are passed to cy_tick().
/// Future expansion: add wildcard subscribers that match topic names by pattern. Requires unbounded dynamic memory.
///
/// Creation of a new subscription will involve network transactions unless the subject-ID is already known or is fixed.
/// However, the operation is non-blocking --- the message will be enqueued and sent in the background.
cy_err_t cy_sub_new(struct cy_t* const       cy,
                    struct cy_topic_t* const topic,
                    struct cy_sub_t* const   sub,
                    const size_t             extent,
                    const uint64_t           tfer_id_timeout_us,
                    void (*const callback)(const struct cy_sub_event_t*));
void     cy_sub_del(struct cy_topic_t* const topic, struct cy_sub_t* const sub);

cy_err_t cy_pub(struct cy_t* const        cy,
                struct cy_topic_t* const  topic,
                const uint64_t            tx_deadline_us,
                const struct cy_payload_t payload);

#ifdef __cplusplus
}
#endif
