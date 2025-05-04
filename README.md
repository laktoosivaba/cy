# Robust zero-configuration decentralized Cyphal with named topics

An experiment in robust zero-configuration pub-sub based on CRDT that works anywhere. The design favors availability and guarantees eventual consistency. Brief periods of degraded service are possible when new nodes or new topics are introduced into the network. A fully settled network is guaranteed to function deterministically just like a statically configured one; however, the initial settling process is stochastic in its nature. A found steady configuration can be stored to allow instant deterministic state recovery at every boot, while this state does not have to be pre-configured manually like in the original design.

The solution does not require special nodes (e.g., master nodes) and is fully stateless protocol-wise. Full implementation in C takes only a few hundred lines of code, does not require dynamic memory at all, and adds virtually zero error states.


## Basic principles

The solution allows one to perform pub/sub on named topics (as opposed to using integer identifiers) and to obviate the need for node-ID allocation. Thanks to this, a Cyphal network can become operational from scratch without any mandatory configuration steps --- no need to assign the node-IDs, no need to use special allocator nodes, no need to configure subject-IDs. A Cyphal node will simply appear in the network and be ready to pub/sub.

A new unique-ID, or UID, is introduced to partially replace the old node-ID and the 128-bit unique-ID. The new UID is composed of a 16-bit vendor-ID regulated by the OpenCyphal maintainers (a vendor must apply to get a unique VID), 16-bit product-ID, and 32-bit instance-ID.

The node-ID is now chosen by each node randomly at bootup, somewhat similar to mechanisms available in IPv6, and all incoming traffic is continuously monitored for collisions. If a collision is found, a very simple stochastic algorithm is applied to rectify it (roll a dice and either do nothing or pick a new random address with probability $q$; interestingly, the optimal choice of $q$ depends on the address space congestion). Once a conflict-free node-ID is found, it can be stored in a non-volatile memory to ensure the network is immediately conflict-free on the next bootup (unless new nodes are introduced). This algorithm will be referred to as the "optimistic DAD" (DAD for duplicate address detection; optimistic because we simply redraw a random number per collision without any further considerations). The probabilistic analysis of this problem is nontrivial.

The subject-IDs for named topics are chosen by all nodes in consensus using a kind of conflict-free replicated data type (CRDT) using a simple and fully stateless protocol relying only on the (modified) heartbeat message for communication. The CRDT is a mapping between topic name and its subject-ID. CRDT entries are constantly exchanged between nodes to let them stay in sync, and to cross-check each other. When a node needs to utilize a named topic, it will consult with its local copy of the table. If such entry is found, it is used as-is. If no such entry is found, the local node will speculatively allocate a new entry, add it to the table, and immediately publish it to let all other nodes incorporate it into their tables, or to object if conflicts are found.

Message loss is not a problem because every node continuously scans and publishes every entry from its table. Should a loss occur, it will be mitigated at the next scan performed by any online node that knows this topic. Every node needs only to keep table entries that it uses itself.

When a new entry needs to be added, the new subject-ID proposal is computed as a deterministic hash from the topic name, mapping the name into `[0, 6144)`. It is important that the hash is deterministic. Several nodes attempting to pub/sub on the same topic while residing in partitioned parts of the network will still agree on the specific subject-ID. That is, unless there is a hash collision. Given 6144 possible hash values, the probability of two topics colliding is only 0.016%; however, this probability grows nonlinearly with the number of topics (birthday paradox): at 100 topics the collision probability is already 55.5%.

A collision will be discovered and remedied by the normal CRDT gossip protocol eventually as will be described below; however, this promise of an eventual resolution is not good enough because while the CRDT is making its slow progress, much faster application data streams may be exchanged over the conflicting subjects, which is disastrous as it may cause data misinterpretation by the application. To avoid this, the transport layer is extended with a stochastic multiple occupant monitoring (stochastic MOM) based on a topic name hash, called discriminator, attached to every transport frame; this is a no-brainer for all transports (in UDP and serial there is an unused 16-bit header field already) except Cyphal/CAN, where slightly different reasoning applies (discussed separately). The transport libraries (libudpard, libserard, etc.) will be modified to check for the topic name hash correctness for all incoming frames (unless none is defined for a given subscription, which is the case for the ordinary unnamed old v1 subjects); similarly, it will populate the topic discriminator for all outgoing frames. This simple remedy will allow the transport layer to function even in the face of a subject collision, albeit in a degraded mode, while waiting for CRDT to resolve the problem.

It is essential that the topic name hash functions used for the discriminator and for choosing the subject-ID are distinct to minimize collisions. Since implementations are already likely to use some large hash for topic indexing (like AVL tree), we can just use (CRC64 % 6144) for deterministic topic-ID selection, and (CRC64>>16) for topic discriminator.

If a discriminator mismatch is found on the transport layer, a notification is delivered to the CRDT layer to let it rectify the situation. In the ideal scenario, we would have relied on the Lamport clock and UID to decide which topic needs to move to a new subject-ID; however, when we get a collision alert from the transport layer we don't know which other topic is infringing on our subject, all we know is that someone is. There are two major approaches here:

1. Instead of making new subject-ID allocations using a deterministic hash function, simply pick them at random.
2. Introduce a kind of nonce to allow multi-round picks per topic name, such that different topic names cause the hash functions to take different trajectories.

The first one, where we simply pick random numbers instead of deterministic allocations, is very simple, but it has two issues: 1. partitioned networks will allocate differently, which will require moving topics between subjects after de-partitioning (not a deal breaker but it does cause a transient disruption); 2. networks with a large number of topics will require many random picks to settle. The specific number of steps can be derived analytically, but the derivation (based on dynamic programming) is a computationally hard problem. A simpler Monte-Carlo simulation predicts that a network with 1000 topics will require more than 5 picking rounds to settle with a probability of ~10%; the probability that more than 8 rounds are needed is negligible. For 3000 topics, the probability of needing more than 15 picking rounds is almost 4%.

Given $k=2$ actors competing for the same identifier, the strategy to settle on distinct identifiers in the least number of turns is to let each pick a new value at each turn. If $k$ is large, the optimal strategy is to let each actor do nothing upon collision detection with some probability $q$; it makes sense because if all actors redraw, the original slot that caused the collision will remain empty. The basic case of $q=1$ works well for small networks where the number of nodes $N$ is much less than the address space $M$ (128 for Cyphal/CAN, 65534 for the other transports). At higher $N$, the optimal $q$ is reduced. See `optimistic_dad_montecarlo.py`.

A Monte-Carlo simulation of the topic allocation problem in a network of 3000 topics yields best results of 34 rounds with $q=0.5$ (even 0.4 and 0.6 yield poorer results). Same with 1000 topics reaches consensus in 8 rounds with $q=0.75$ (11 rounds with $q=0.5$).

This problem has commonalities with the ordinary retry-backoff CSMA/CD, where instead of drawing numerical identifiers, participants compete for the air time. Since $N$ is not statically known, one idea here is to slowly exponentially reduce $q$ at every collision (e.g., $q^\prime = 0.95 q$) from the original value of one, until some reasonable minimum (0.5) is reached. Another desirable side effect is that a node that has seen more collisions will be more likely to keep its allocated value, meaning that newcomers will be more likely to adapt to the network than the other way around.

Monte-Carlo simulation predicts that for CAN, a network with 32 nodes has the optimal $q \approx 0.75$, allowing it to settle in under 8 steps almost always. With 64 nodes, $q \approx 0.5$ yields better results of at most 23 draws.

Moving on to the second approach: suppose our hash function applied to two distinct topic names yields the same $s$, thus a collision. To allow the algorithm to make progress, the next round must be likely to yield distinct hash values despite the collision at this round. **THERE IS INTEREST IN APPLYING A SIMILAR STRATEGY TO THE OPTIMISTIC DAD**, where, for example, the initial node-ID is some hash of the UID, and every subsequent pick drives each node-ID along its unique trajectory defined by the UID. It is unclear yet if this is statistically sensible.

A possible middle-ground solution could be to choose the first allocation deterministically, and use random draws if a collision is found. Every time a collision is handled, $q$ will exponentially decay as outlined above until it reaches some low value.


## Heartbeat extension

```python
# TopicGossip

UID.0.1 owner_uid       # For tie breaking within the same Lamport clock.
uint32  lamport_clock   # Assume the lag will not exceed 2**31-1 ticks.
uint32  ttl_ms          # [milliseconds] Value eligible for reuse in approx. this time.
uint16  value           # Ignore if the name is empty.
void48

@assert _offset_ == {192}
utf8[<=80] name         # Name offset is 25 bytes (200 bits) from the message origin.

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
