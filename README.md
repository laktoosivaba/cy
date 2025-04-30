# Cyphal named topics design

An experiment in robust zero-configuration pub-sub based on CRDT that works anywhere. The design favors availability and guarantees eventual consistency. Brief periods of degraded service are possible when new nodes or topics are introduced into the network. A fully settled network is guaranteed to function just like a statically configured one. A found steady configuration can be stored to allow instant state recovery at every boot, without the usual initial period of degraded service while consensus is sought.

The solution does not require special nodes (e.g., master nodes) and is fully stateless protocol-wise.


## Heartbeat extension

```python
# TopicGossip

UID.0.1 owner_uid       # For tie breaking within the same Lamport clock.
uint32  lamport_clock   # Assume the lag will not exceed 2**31-1 ticks.
uint32  ttl_ms          # [milliseconds] Value eligible for reuse in approx. this time.
uint16  value           # Ignore if the name is empty.
void48

@assert _offset_ == {192}
utf8[<=80] name

@sealed
```

## Rules

### When publishing

- Check if the subject-ID is known from the local table.
  - If yes, use that.
  - If not, discard the message and publish a CRDT update with the sought topic name and lamport_clock=0.

RATIONALE:

1. If the subject-ID is not known, there are no online subscribers for this message, so it doesn't make sense to publish it.
2. However, if the publisher has just came online itself, it could be that its local table is lagging behind its actual state, and it has to catch up with the network. To speed this up, we publish an empty entry to solicit the missing information, if available.
3. We DO NOT attempt to choose a subject-ID automatically to avoid possible collisions while the network is converging. Only subscribers are allowed to perform such allocations; this is safe because a subscriber does not disturb the network.
4. The algorithm is stateless and guarantees eventual convergence even in the presence of message loss.


### When asked to subscribe

- Check if the subject-ID is known from the local table.
  - If not, choose a subject-ID using the hash-based algorithm, create a new table entry, and immediately publish that. Remember that if this entry loses arbitration, a corrective entry will be published immediately by other nodes.
- Now, the topic is present in the table. Use that subject-ID.

RATIONALE:

1. If the subject-ID is not known, we are likely the first subscriber on this topic, so we are responsible for bringing it alive by choosing a subject-ID.
2. However, if the subscriber has just came online itself, it could be that its local table is lagging behind its actual state, and it has to catch up with the network. In this case, the local subject-ID assignment will compete with the others available in the network, and it will either lose (when this happens, the correct entry is published immediately), or it will move the entire network to the new subject-ID.


### Every 0.1~1 second

- Pick i++-th local table entry.
  - Reduce ttl_ms, unless the entry is used locally. Simple MCU nodes will only keep entries that they use, so the rule does not apply to them.
  - If ttl_ms==0, assign name="" and reset the value. Increment the Lamport clock. This never takes place in small MCU nodes.
  - Publish heartbeat with the entry. In the theoretical worst case of 6144 alive topics, it takes a little over 10 minutes to scan the entire table, assuming 10 Hz updates. The path through the table should ideally be randomized to avoid multiple nodes publishing the same entries in lockstep (useless).


### When a new heartbeat is received

- If the local node is incapable of keeping the full replica of the table (not enough memory, small MCU), AND the name does not match any of the topic names known to the local node, drop the heartbeat and exit. Nodes that keep the full table are called the oracle nodes.
- Merge the new entry into the local table. Do not actually update the local table if the new entry has version zero -- this means it is a request.
  - If the received entry lost arbitration against the local entry, publish the local entry immediately. This happens if the new entry has version zero (request). Do the same if the received entry is invalid in any other way to help the remote node repair its state.
  - If the local entry lost arbitration against the received entry, silently overwrite the local entry.
    - If, upon overwrite, it turned out that there is another entry with the same subject-ID, re-allocate that subject-ID to a new value (increment the clock) and publish that entry.
  - If the entries are the same, do nothing.
- If the local entry was overwritten, update the local publisher/subscriber/etc, if any.


## Edge cases

### Collision while partitioned

- The network is partitioned into A and B.
- Partition A allocates topic X on ID N.
- Partition B allocates topic Y on ID N due to a topic name hash collision (birthday paradox).
- The paritions are rejoined.
- Now, we have topics X and Y using the same subject-ID N for a while, until the CRDT table has converged (this will happen eventually without any special measures).

SOLUTION:

- All transports except Cyphal/CAN: Add a 16-bit topic name CRC to each message header. We already have a suitable reserved field in the frame headers. On mismatch, drop the frame; the network will eventually converge so this will only cause a temporary service disruption. This way we will segregate mismatching frames from good ones, allowing nodes to communicate even in the face of a collision.

- Cyphal/CAN: no known solution exists; Cyphal/CAN will not be partition-tolerant. One option could be to use some of the four reserved bits in the CAN ID for some kind of topic name hash, but the effect of such a small hash is marginal.


## Changes to the transport libraries: libudpard, libcanard, libserard

### Optimistic DAD

Implement Optimistic DAD as the default node-ID assignment policy, while still allowing fully manual assignments. Optimistic DAD requires access to a good source of randomness, so it will probably be either handed over to the application, or some very long-sequence PRNG algorithm will need to be seeded with a user-provided source of entropy (e.g., a 64-bit seed).

Optimistic DAD requires checking the node-ID on every incoming frame for collisions. If a collision is found, the simple mitigation is performed:

1. In 75% of the cases do nothing --- ignore the collision.
2. In 25% of the cases, pick a new random node-ID. It could be the same as before (very unlikely), which is fine. Done.

### Topic CRC validation

New-style publishers will provide the topic CRC for each outgoing transfer. Subscriptions will provide the expected topic CRC. The transport libraries will need to populate the correct topic CRC when emitting frames, and to weed out incoming frames that have a wrong topic CRC, before even accepting them for reassembly. If the filtering was done at a higher level, this wouldn't be as efficient because removal of non-matching frames still allows nodes to communicate even in the presence of subject-ID collisions; the limitation is that such communication is inefficient.

Old-style pub/sub does not know anything about topic CRCs, so the libraries will need to support that use case as well.

Cyphal/CAN does not really have enough space for the full 16-bit topic CRC. There are only four bits (only three consecutive), which is better than nothing though.

### Topic CRC collision detection

If the transport library detects a topic CRC error, it should notify the higher layer, so that a corrective CRDT gossip entry could be published, allowing the network to heal faster.

