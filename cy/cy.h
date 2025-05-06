/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef CY_CONFIG_TRACE
#define CY_CONFIG_TRACE 0
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/// A sensible middle ground between worst-case gossip traffic and memory utilization vs. longest name support.
/// In CAN FD networks, topic names should be short to avoid multi-frame heartbeats.
///
/// Max name length is chosen such that together with the 1-byte length prefix the result is a multiple of 8 bytes,
/// because it helps with memory-aliased C structures for quick serialization.
#define CY_TOPIC_NAME_MAX 95

/// The max namespace length should also provide space for at least one separator and the one-character topic name.
#define CY_NAMESPACE_NAME_MAX (CY_TOPIC_NAME_MAX - 2)

/// If not sure, use this value for the transfer-ID timeout.
#define CY_TRANSFER_ID_TIMEOUT_DEFAULT_us 2000000L

/// The rate at which the heartbeat topic is published is also the absolute minimum library state update interval.
/// It is not an error to update it more often, and in fact it is desirable to reduce possible frequency aliasing.
#define CY_HEARTBEAT_PERIOD_DEFAULT_us 100000L

/// If a node-ID is provided by the user, it will be used as-is and the node will become operational immediately.
///
/// If no node-ID is given, the node will take some time after it is started before it starts sending transfers.
/// While waiting, it will listen for heartbeats from other nodes to learn which addresses are available.
/// If a collision is found, the local node will immediately cease publishing and restart the node-ID allocation.
///
/// Once a node-ID is allocated, it can be optionally saved in non-volatile memory so that the next startup is
/// immediate, bypassing the allocation stage.
///
/// If a conflict is found, the current node-ID is abandoned regardless of whether it's been given explicitly or
/// allocated automatically.
///
/// TODO this goes to the transport layer; see below why.
#define CY_START_DELAY_MIN_us (CY_HEARTBEAT_PERIOD_DEFAULT_us * 5)
#define CY_START_DELAY_MAX_us (CY_START_DELAY_MIN_us * 5)

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
#define CY_NODE_ID_INVALID    0xFFFFU

typedef int32_t cy_err_t;
typedef int64_t cy_us_t; ///< Monotonic microsecond timestamp. Signed to permit arithmetics in the past.

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

/// An ordinary Bloom filter with 64-bit words.
struct cy_bloom64_t
{
    size_t    n_bits; ///< The total number of bits in the filter, a multiple of 64.
    uint64_t* storage;
};

struct cy_transfer_meta_t
{
    enum cy_prio_t priority;
    uint16_t       remote_node_id;
    uint64_t       transfer_id;
};

/// Returns the current monotonic time in microseconds. The initial time shall be non-negative.
typedef cy_us_t (*cy_now_t)(struct cy_t*);

/// Instructs the underlying transport to adopt the new node-ID.
/// This is invoked either immediately from cy_new() if an explicit node-ID is given,
/// or after some time from cy_heartbeat() when one is allocated automatically.
/// When this function is invoked, cy_t contains a valid node-ID.
typedef cy_err_t (*cy_transport_set_node_id_t)(struct cy_t*);

/// Instructs the underlying transport to abandon the current node-ID. Notice that this function is infallible.
/// This is invoked only if a node-ID conflict is detected; in a well-managed network this should never happen.
/// If the transport does not support reconfiguration or it is deemed too complicated to support,
/// one solution is to simply restart the node.
/// It is recommended to purge the tx queue to avoid further collisions.
typedef void (*cy_transport_clear_node_id_t)(struct cy_t*);

/// Instructs the underlying transport layer to publish a new message on the topic.
/// The function shall not increment the transfer-ID counter; Cy will do it.
typedef cy_err_t (*cy_transport_publish_t)(struct cy_topic_t*, cy_us_t, struct cy_payload_t);

/// Instructs the underlying transport layer to create a new subscription on the topic.
typedef cy_err_t (*cy_transport_subscribe_t)(struct cy_topic_t*);

/// Instructs the underlying transport to destroy an existing subscription.
typedef void (*cy_transport_unsubscribe_t)(struct cy_topic_t*);

/// If a subject-ID collision or divergence are discovered, Cy may reassign the topic to a different subject-ID.
/// To do that, it will first unsubscribe the topic using the corresponding function,
/// and then invoke the subscription function to recreate the subscription with the new subject-ID.
///
/// The unsubscription function is infallible, but the subscription function may fail.
/// If it does, this callback will be invoked to inform the user about the failure,
/// along with the error code returned by the subscription function. It is up to the user to repair the problem.
/// If the user does nothing, the topic will be simply left in the unsubscribed state, as if
/// cy_topic_subscribe() was never invoked. However, if the topic needs to be moved again in the future,
/// Cy will use that opportunity to attempt another subscription, which may or may not succeed.
///
/// A possible failure handling strategy is to record which topic has failed and to keep trying to re-subscribe
/// in the background until it succeeds. Once the subscription is successful, no additional actions are needed.
/// It is probably not useful to try and invoke cy_subscribe() immediately from the error handler.
typedef void (*cy_transport_handle_resubscription_err_t)(struct cy_topic_t*, const cy_err_t);

/// Transport layer interface functions.
/// These can be underpinned by libcanard, libudpard, libserard, or any other transport library.
struct cy_transport_io_t
{
    cy_transport_set_node_id_t               set_node_id;
    cy_transport_clear_node_id_t             clear_node_id;
    cy_transport_publish_t                   publish;
    cy_transport_subscribe_t                 subscribe;
    cy_transport_unsubscribe_t               unsubscribe;
    cy_transport_handle_resubscription_err_t handle_resubscription_err;
};

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
    /// For pinned topics, the name hash equals the subject-ID.
    uint64_t hash;

    /// Whenever a topic conflicts with another one locally, arbitration is performed, and the loser has its
    /// defeat counter incremented. The defeat counter is used as a Lamport clock counting the loss events.
    /// Higher Lamport clock (defeat counter) wins because it implies that any lower value is non-viable since
    /// it has been known to cause at least one collision anywhere on the network.
    /// The counter MUST NOT BE CHANGED without removing the topic from the subject-ID index tree!
    /// When a topic is defeated, it loses its respect and has to re-earn it from zero.
    /// Remember that the subject-ID is (for non-pinned topics): (hash+defeats)%topic_count.
    uint64_t defeats;

    /// Ranks this topic by how widely it is used on the network AND by its age.
    /// The initial value is zero and it grows with time, the rate of growth is determined by the number of users.
    ///
    /// Topics with greater respect are less likely to be defeated, which is a critical property for ensuring
    /// stability of the network. In a conflict, more respected topic stays, while newcomers and rarely used
    /// topics that are yet to earn respect have to adapt. When a topic is defeated, its respect is reset to zero.
    ///
    /// A topic that nobody else is using will keep its respect at zero, reflecting the fact that it can be moved
    /// at no cost without disrupting communication.
    ///
    /// The respect counter is a CRDT G-counter which also serves as a Lamport clock.
    /// The merge operation is performed whenever a gossip message of this topic is received as: R'=max(R,R_other)+1.
    /// This value is useful for logical event ordering, but it is not an accurate representation of the actual usage
    /// of the topic in the network, because the increment rate depends on the gossip rate of the topic info by others,
    /// which in turn depends on the heartbeat rates of the other participants and on the number of other topics they
    /// have to round-robin through.
    uint64_t respect;

    /// Updated whenever the topic is gossiped.
    ///
    /// Notably, this is NOT updated when we receive a gossip from another node. While this approach can reduce
    /// redundant gossip traffic (no need to publish a gossip when the network just saw it), it can also lead to
    /// issues if the network is semi-partitioned such that the local node straddles multiple partitions.
    /// This could occur in packet switched networks or if redundant interfaces are used. Such coordinated publishing
    /// can naturally settle on a stable state where some nodes become responsible for publishing specific topics,
    /// and nodes that happen to be in a different partition will never see those topics.
    cy_us_t last_gossip_us;

    /// The user can use this field for arbitrary purposes.
    void* user;

    /// Only used if the application publishes data on this topic.
    /// The priority can be adjusted as needed by the user.
    uint64_t       pub_transfer_id;
    enum cy_prio_t pub_priority;

    /// Only used if the application subscribes on this topic.
    struct cy_subscription_t* sub_list;
    cy_us_t                   sub_transfer_id_timeout_us;
    size_t                    sub_extent;
    bool                      subscribed; ///< May be false even if sub_list is nonempty on resubscription error.
};

/// Cy will free the payload buffer afterward. The application cannot keep it beyond the callback because the memory
/// could be allocated from the NIC buffers etc.
typedef void (*cy_subscription_callback_t)(struct cy_subscription_t* subscription,
                                           cy_us_t                   timestamp_us,
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
    /// the inner structure of the UID; all it needs is a number to order the nodes on the network and to seed PRNG.
    /// Zero is not a valid UID.
    uint64_t uid;

    cy_us_t started_at_us;

    uint16_t node_id;
    uint16_t node_id_max; ///< Depends on the transport layer.

    /// The size of the address occupancy Bloom filter effectively limits the maximum number of nodes that can be
    /// statelessly auto-allocated in the network. More nodes can be added only if manual address assignment is used.
    /// Nodes on the network may have different Bloom filter sizes, as it does not affect their compatibility.
    ///
    /// A filter composed of 64x64-bit words can support up to 4096 auto-allocated nodes per network, which is a safe
    /// choice for most Cyphal networks.
    /// For Cyphal/CAN, a single 64-bit word is sufficient, since CAN networks with >64 nodes are exceedingly rare.
    struct cy_bloom64_t node_id_bloom;

    /// The user can use this field for arbitrary purposes.
    void* user;

    /// Namespace prefix added to all topics created on this instance, unless the topic name starts with "/".
    size_t namespace_length;
    char   namespace_[CY_NAMESPACE_NAME_MAX + 1];

    cy_now_t                 now;
    struct cy_transport_io_t transport;

    /// Heartbeat topic and related items.
    struct cy_topic_t*       heartbeat_topic;
    struct cy_subscription_t heartbeat_sub;
    cy_us_t                  heartbeat_next_us;
    cy_us_t                  heartbeat_period_us; ///< Can be adjusted by the user. Prefer larger period on CAN.

    /// Topics have multiple indexes.
    struct cy_tree_t* topics_by_hash;
    struct cy_tree_t* topics_by_subject_id;
    struct cy_tree_t* topics_by_gossip_time;

    /// This is to ensure we don't exhaust the subject-ID space.
    size_t topic_count;
};

/// If node_id > node_id_max, it is assumed to be unknown, so a stateless PnP node-ID allocation will be performed.
/// If a node-ID is given explicitly, a heartbeat will be published immediately to claim it. If the ID
/// is already taken by another node, it will have to move. This behavior differs from the normal node-ID
/// autoconfiguration process, where a node will make sure to avoid conflicts at the beginning to avoid disturbing
/// the network; the rationale is that a manually assigned node-ID takes precedence over the auto-assigned one,
/// thus forcing any squatters out of the way.
///
/// The namespace may be NULL or empty, in which case it defaults to "~".
///
/// The node-ID occupancy Bloom filter is used to track the occupancy of the node-ID space. The filter must be at least
/// a single 64-bit word long. The number of bits in the filter (64 times the word count) defines the maximum number
/// of nodes present in the network while the local node is still guaranteed to be able to auto-configure its own ID
/// without collisions. The recommended parameters are two 64-bit words for CAN networks (takes 16 bytes) and
/// 64~128 words (512~1024 bytes) for all other transports.
///
/// The heartbeat_topic must point to an uninitialized topic structure that will be used to publish heartbeat messages;
/// this is the only topic that is needed by Cy itself. It will be initialized and managed automatically; if necessary,
/// the user can add additional subscriptions to it later.
///
/// No network traffic will be generated. The only function that can send heartbeat messages is cy_heartbeat().
cy_err_t cy_new(struct cy_t* const             cy,
                const uint64_t                 uid,
                const uint16_t                 node_id,
                const uint16_t                 node_id_max,
                const size_t                   node_id_occupancy_bloom_filter_64bit_word_count,
                uint64_t* const                node_id_occupancy_bloom_filter_storage,
                const char* const              namespace_,
                struct cy_topic_t* const       heartbeat_topic,
                const cy_now_t                 now,
                const struct cy_transport_io_t transport_io);
void     cy_destroy(struct cy_t* const cy);

/// This is invoked whenever a new transfer on the topic is received.
/// The library will dispatch it to the appropriate subscriber callbacks.
/// Excluding the callbacks, the time complexity is constant.
///
/// If this is invoked together with cy_heartbeat(), then cy_ingest() must be invoked BEFORE cy_heartbeat()
/// to ensure that the latest state updates are reflected in the next heartbeat message.
void cy_ingest(struct cy_topic_t* const        topic,
               const cy_us_t                   timestamp_us,
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
/// This function is also responsible for handling the local node-ID allocation.
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

/// When the transport library detects an incoming transport frame with the same source node-ID as the local node-ID,
/// it must notify Cy about it to let it rectify the problem. This function will immediately invoke
/// transport.clear_node_id() and commence the new node-ID allocation process.
/// Note that the node-ID collision checks must be done on raw transport frames, not on reassembled transfers, for
/// two reasons: 1. this is faster, allowing quick reaction; 2. in the presence of a node-ID conflict, transfers
/// arriving from that ID cannot be robustly reassembled.
///
/// TODO FIXME MOVE THIS TO THE TRANSPORT LIBRARY INSTEAD! REASONS WHY:
/// 1. This check operates at the frame level, not transfer level, which is too low for Cy; this is why we need this
/// function as opposed to just handling things in cy_ingest.
/// 2. The node-ID space and the optimal allocation strategy (Bloom filter size) are dependent on the transport layer!
/// 3. HETEROGENEOUS REDUNDANT INTERFACES MAY HAVE TO USE DIFFERENT NODE-IDS, and attempting to allocate a shared one
/// is at least inefficient, at most impossible!
/// 4. With named topics in place, no entity above the transport layer cares about the node-ID value.
void cy_notify_node_id_collision(struct cy_t* const cy);

/// If a node-ID is given explicitly at startup, it will be used as-is and the node will become operational immediately.
/// Otherwise, some initial node-ID autoconfiguration time will be needed before the local ID is available.
/// Also, if a node-ID conflict is found at any later time (e.g., if a badly configured node joins the network),
/// the current ID will be abandoned and after some time a new one will be allocated. This cannot happen in a
/// well-managed network. A node with an auto-configured ID will not encroach on the IDs of other nodes by design.
///
/// An attempt to emit a transfer while the local node-ID is missing may fail, depending on the transport library.
static inline bool cy_has_node_id(const struct cy_t* const cy)
{
    return cy->node_id <= cy->node_id_max;
}

/// Register a new topic that may be used by the local application for publishing, subscribing, or both.
/// Returns falsity if the topic name is not unique or not valid.
/// Pinned topics should not use subject-IDs below CY_ALLOC_SUBJECT_COUNT because the network may have to move them.
/// No network traffic is generated here.
/// TODO: provide an option to restore a known subject-ID; e.g., loaded from non-volatile memory, to skip allocation.
bool cy_topic_new(struct cy_t* const cy, struct cy_topic_t* const topic, const char* const name);
void cy_topic_destroy(struct cy_topic_t* const topic);

/// Complexity is logarithmic in the number of topics. NULL if not found.
struct cy_topic_t* cy_topic_find_by_name(struct cy_t* const cy, const char* const name);
struct cy_topic_t* cy_topic_find_by_hash(struct cy_t* const cy, uint64_t hash);
struct cy_topic_t* cy_topic_find_by_subject_id(struct cy_t* const cy, uint16_t subject_id);

/// Iterate over all topics in arbitrary order.
/// This is useful when handling IO multiplexing (building the list of descriptors to read) and for introspection.
/// The function does nothing if the cy or callback are NULL.
void cy_topic_for_each(struct cy_t* const cy,
                       void (*callback)(struct cy_topic_t* const topic, void* const user),
                       void* const user);

uint16_t cy_topic_get_subject_id(const struct cy_topic_t* const topic);

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
/// Invoking this function on the same cy_subscription_t instance multiple times is allowed and will have no effect
/// if the subscription is already active. This use case is added specifically to allow repairing broken
/// resubscriptions when Cy attempts to move the topic to another subject-ID but fails to subscribe it.
///
/// Future expansion: add wildcard subscribers that match topic names by pattern. Requires unbounded dynamic memory.
///
/// It is allowed to remove the subscription from its own callback, but not from the callback of another
/// subscription.
cy_err_t cy_subscribe(struct cy_topic_t* const         topic,
                      struct cy_subscription_t* const  sub,
                      const size_t                     extent,
                      const cy_us_t                    transfer_id_timeout_us,
                      const cy_subscription_callback_t callback);
void     cy_unsubscribe(struct cy_topic_t* const topic, struct cy_subscription_t* const sub);

/// The transfer-ID is always incremented, even on failure, to signal lost messages.
/// Therefore, the transfer-ID is effectively the number of times this function was called on the topic.
/// This function always publishes only one transfer as requested; no auxiliary traffic is generated.
/// If the local node-ID is not allocated, the function may fail depending on the capabilities of the transport library;
/// to avoid this, it is possible to check cy_has_node_id() before calling this function.
cy_err_t cy_publish(struct cy_topic_t* const topic, const cy_us_t tx_deadline_us, const struct cy_payload_t payload);

/// Make topic name canonical. The output buffer shall be at least CY_TOPIC_NAME_MAX + 1 bytes long.
/// Returns positive length on success, zero if the name is not valid.
/// Example: "/foo//bar/" -> "/foo/bar"
size_t cy_canonicalize_topic(const char* const in, char* const out);

/// For diagnostics and logging only. Do not use in embedded and real-time applications.
/// This function is only required if CY_CONFIG_TRACE is defined and is nonzero; otherwise it should be left undefined.
/// Other modules that build on Cy can also use it; e.g., transport-specific glue modules.
extern void cy_trace(struct cy_t* const  cy,
                     const char* const   file,
                     const uint_fast16_t line,
                     const char* const   func,
                     const char* const   format,
                     ...)
#if defined(__GNUC__) || defined(__clang__)
  __attribute__((__format__(__printf__, 5, 6)))
#endif
  ;

/// This convenience macro is defined in the header file to enable reuse in other modules.
/// The newline at the end is not included in the format string.
#if CY_CONFIG_TRACE
#define CY_TRACE(cy, ...) cy_trace(cy, __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define CY_TRACE(cy, ...) (void)0
#endif

#ifdef __cplusplus
}
#endif
