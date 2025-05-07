# Robust zero-configuration decentralized (brokerless) Cyphal with named topics

An experiment in robust zero-configuration pub-sub based on CRDT that works anywhere. The design favors availability and guarantees eventual consistency. Brief periods of degraded service are possible when new nodes or new topics are introduced into the network. A fully settled network is guaranteed to function deterministically just like a statically configured one; however, the initial settling process is stochastic in its nature. A found steady configuration can be stored to allow instant deterministic state recovery at every boot, while this state does not have to be pre-configured manually like in the original design.

The solution does not require special nodes (e.g., master nodes) and is fully stateless protocol-wise. Full implementation in C takes only a few hundred lines of code, does not require dynamic memory at all, and adds virtually zero error states.


## Heartbeat extension

```python
# 7509.cyphal.node.Heartbeat.2
uint32    uptime          # [second] like in Heartbeat v1
void16                    # Used to be health and mode
uint16    user_word       # Used to be vendor-specific status code
UID.0.1   uid             # New field: 64-bit unique node ID
@assert _offset_ == {128}
Gossip.0.1 gossip         # CRDT gossip data
@sealed
```

```python
# Gossip
uint64[3] value
uint64    key_hash
uint8 KEY_CAPACITY = 95
utf8[<=KEY_CAPACITY] key
```

## Rules

### When publishing

Just publish using the current subject-ID mapping.

The mapping is guaranteed to be correct except during the initial configuration stage. By design, once a stable mapping is found, it will be retained by the current topic, with all new arrivals (e.g., new nodes joining the network, or existing nodes advertising new topics) will be forced to find new subject-IDs.

Applications that require immediate connectivity without the initial configuration delays can store the stable configuration in non-volatile memory.

While the initial configuration is in progress, transfers may be emitted on the wrong subject-IDs, which causes data loss. The 51-bit topic discriminator is used to avoid data misinterpretation.

### When asked to subscribe

Just use the current subject-ID mapping.

If the consensus algoritm later finds a different mapping (e.g., an older topic is found and we need to move), the old subscription will be destroyed and replaced with a new one in the background (this happens from the `on_heartbeat` context).

#### When a message is received

Incement the age counter of the current topic.

### When a new heartbeat is published

1. Using the last gossip time index, pick the topic with the oldest last gossip time.
2. Increment the age counter.
3. Publish the heartbeat with the KV gossip.

### When a new heartbeat is received

TODO


## Missing features

### RPC calls

These are much easier since they require no consensus -- each node does its own allocations locally.
To avoid data corruption on sudden node-ID reassignment, the transfer should include either the destination UID or its hash.

### Wildcard topic subscriptions

This is not a protocol feature but a library feature, which is easy to add.
The protocol requires no (nontrivial) changes to incorporate this.


## Changes to the transport libraries: libudpard, libcanard, libserard, etc.

### Pessimistic DAD

Implement the pessimistic duplicate address detection (DAD) method as the new node-ID assignment policy, while still allowing fully manual assignments for the benefit of applications that require full control over the transport.

The Pessimistic DAD requires a long-sequence PRNG, which can be as simple as the standard SplitMix64 or Rapidhash seeded with the node's 64-bit UID. In addition, a large Bloom filter is needed: 8~16 bytes for Cyphal/CAN, 512~1024 bytes for the other transports.

The transport libraries will be fully responsible for managing the node-ID, unless it is assigned manually. Even in the case of manual assignment, the collision monitoring will be done continuously for safety reasons; shall a collision be discovered, the current node-ID will be abandoned regardless of whether it's assigned manually or automatically.

The application will need to be notified when the local node-ID is changed to perform some transport-specific migration activities:
- Cyphal/UDP: rebind the RPC RX socket to the new mcast endpoint.
- Cyphal/CAN: update the acceptance filter for RPC frames.

The overall cost of the Pessimistic DAD is about 100~200 extra lines of code per transport library.

### Extensions to support Stochastic MOM

Stochastic multiple occupant monitoring (MOM) mixes parts of the 51-bit topic discriminator (which itself is defined as the 51 most significant bits of the 64-bit topic hash) into the transfer such that only transfers that carry the expected topic discriminator can be correctly received. This prevents data misinterpretation during the topic allocation phase, when multiple topics may briefly occupy the same subject-ID until the new conflict-free consensus is found by the network. How the topic discriminator is leveraged depends on the specific transport.

When the transport detects a topic discriminator mismatch, it has the option to notify the CRDT protocol so that it can assign a higher priority to the topic where the conflict is found. It is not essential because even if no such notification is delivered, CRDT will eventually reach a conflict-free consensus, but the time required may be longer.

#### Cyphal/UDP and Cyphal/serial

The 16-bit user data field of the frame header will contain some of the 16 bits of the topic discriminator. Other 32 bits will be inverted and the result will be used to seed the transfer-CRC; the current initial value of the transfer-CRC is 0xFFFFFFFF, meaning that pinned topics (whose discriminator is zero) will remain compatible with the old non-named topics. The three leftover bits could be discarded or used to populate a new small field of the header.

This results in a very wide hash (6144 subject-IDs times 2^16 in the user word times 2^32 in the transfer CRC seed, also the optional three leftover bits could be added) that is expected to scale to very large networks even with thousands of topics.

#### Cyphal/CAN

The CAN ID format only offers two bits for the topic discriminator: 21 and 22. Other 16 bits will be used to seed the 16-bit transfer-CRC (the default initial value of CRC-16-CCITT-FALSE is already zero).

The collision detection capability of this scheme is poor as we only introduce 18 bits of hash, which means that named-topic networks based on CAN will not scale to large numbers of topics. Together with 6144 possible subject-ID values, the probability of an undetected discriminator collision given 40 topics (optimistically assuming perfect hashing, which is not accurate) is 4.8e-7, or one in two million. The real probability is likely to be substantially higher, especially considering the limitations of CRC algorithms when used for hashing. Usage of this mechanism in larger CAN networks (more than a couple dozens of topics) is unsafe and requires changes to the CAN frame format.
