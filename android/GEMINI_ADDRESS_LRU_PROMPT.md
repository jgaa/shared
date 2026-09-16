# Gemini prompt: align Android address discovery with the current protocol

Work in the Android implementation of the Shared repository. Read `spec/PROTOCOL.md`, especially “Discovery and Address Hints”, and compare it with:

* `android/app/src/main/java/eu/lastviking/android/shared/peering/PeerService.kt`
* `android/app/src/main/proto/shared.proto`
* the Qt reference behavior in `desktop/src/core/src/address_hint_repository.cpp`
* the Qt integration behavior in `desktop/src/daemon/src/peer_service.cpp`

Implement the Android side of the address-cache/LRU protocol. Do not change protobuf field numbers or introduce a new wire format.

Required behavior

1. Replace the current whole-list assignment behavior with a concurrency-safe per-peer ordered address cache. The order is MRU first and each peer may retain at most five distinct IP addresses.
2. Treat IP as the cache identity. Two entries with the same IP are alternatives for the same cache slot even if their ports or sources differ.
3. Apply source precedence when the same IP has competing entries: `manual` > `local` > `direct` > `observed` > unknown/other. A lower-precedence entry must not displace a higher-precedence entry.
4. For locally learned and directly observed updates, touch the selected entry and move it to the MRU front.
5. For addresses received in `PeerInfo.known_addresses` or `AddressHint.addresses`, merge rather than replace. Treat incoming lists as newest-first and preserve that ordering. An exact duplicate—same IP, port, source, and `observed_time_ms`—must not move in the LRU list and must not report a change.
6. Ignore entries with an empty IP or port zero. Enforce the five-distinct-IP limit before storing, sending, or forwarding.
7. When a received hint causes a real cache change, forward the accepted bounded hint to every authenticated peer except the connection it arrived on. Do not forward or otherwise churn the cache for an exact duplicate. Change `handleAddressHint` so it receives the source `PeerConnection`.
8. Merge `PeerInfo.known_addresses` using the same remote-gossip rules. Do not overwrite addresses already learned from other sources.
9. Record a successfully authenticated peer's socket address as an `observed` entry, using the peer's advertised `listen_port` when nonzero and the socket peer port otherwise. Preserve the existing timestamp for an identical observation so keepalives/reconnect bookkeeping does not create gossip churn. Add narrow read-only remote-address accessors to `PeerConnection` if needed; do not expose or share the mutable socket itself.
10. Keep the local peer's `local` entries synchronized with current non-loopback interface addresses, without discarding its other source entries. Publish at most five entries.
11. Correct outbound candidate ordering to `manual`, `local`, `direct`, then other dialable sources, preserving MRU order inside a priority group. Never dial `observed`. Continue skipping self addresses and invalid endpoints.
12. Set `PeerInfo.listen_port` to 47124 only while the Android mTLS listener is enabled; otherwise send zero. Include the bounded current cache for the local peer in `known_addresses`.
13. Avoid concurrent duplicate outbound attempts by tracking pending peer IDs separately from authenticated connections, and clear that state on every success/failure path. This is necessary because the connection loop can run while address gossip triggers new work.

Persistence is desirable if the existing `PeeringRepository` can support it cleanly. If persistence is added, retain cache order and all four address fields across service restarts. Do not store more than five entries per peer.

Tests

Extract the cache merge/order logic into a small independently testable Kotlin class rather than embedding it all in `PeerService`. Add unit tests covering:

* insertion and MRU ordering
* eviction of the least-recently-used IP after the sixth distinct IP
* deduplication by IP
* source-precedence replacement and preservation
* local/direct updates refreshing MRU position
* exact remote duplicates not refreshing MRU position or reporting a change
* remote updates with changed fields reporting a change
* preservation of newest-first order for multi-address incoming lists
* filtering empty IPs and zero ports
* outbound filtering of `observed` and stable priority ordering
* merging a partial `AddressHint` without deleting previously known endpoints

Run the Android unit tests and build the relevant debug variant. Keep the change focused on address discovery/cache behavior; do not redesign enrollment, transfers, topology, or protobuf messages. In the final response, summarize changed files, behavioral decisions, and test/build results.
