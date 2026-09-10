# TX queue ownership regressions

The software EDCA queue must retain a frame until the radio finishes, then either
return its result to the current caller or release its buffer. Cancelled callers
must not poison a later occupant of the same ring slot or exhaust the buffer pool.

Run the host tests from any directory with Rust 1.90.0 or newer:

```sh
./tests/run-tx-queue.sh
./tests/run-tx-queue.sh --release --features small-pool
```

The standalone test crate includes the actual `foa/src/tx_queue.rs` and
`foa/src/tx_buffer_management.rs`, using the real embassy synchronization and
buffer-pool implementations. Only the radio endpoint is replaced: its completion
can be held pending, completed successfully, or completed with an ACK timeout.
The wrapper runs Cargo outside the firmware workspace to avoid the ESP linker
and `build-std` settings. A committed lockfile makes the host dependencies
reproducible. The default pool has eight buffers; `small-pool` uses three to
exercise ring indexing at a non-power-of-two capacity.

The fifteen tests cover:

- Exactly a full queue of live handles, and repeated successful waits across
  multiple ring-slot reuse cycles.
- Old handles and delayed completed futures dropped after slot reuse; overwritten
  completions return `None` without cancelling the current generation.
- Mixed awaited and fire-and-forget frames, preserving payloads and both success
and error results.
- Cancellation before pickup, during an awaited radio operation, and after a
  completion was saved. A cancelled active transmission keeps its buffer until
  the radio completes. Every cancellation path recovers all pool buffers and
  permits another allocation and awaited transmission.
- Actual waker notification when an empty runner receives work, when a waiting
  caller receives a completion, and when dropping an unclaimed completion frees
  a buffer for a blocked allocator.
- An aborted runner releasing its frame and resolving the caller with `None`.
- Counter exhaustion rejected before changing a slot or queue capacity, in debug
  and release configurations.

The original queue counted `next_generation - handle_generation == capacity` as
expired, even though that slot had not yet been overwritten. It also inherited
completion interest from a slot's previous caller, allowed a stale handle to
clear a new caller's interest, and captured interest before awaiting the radio.
Dropping an already completed handle left its buffer retained indefinitely. Those
paths could discard valid completion results or leave every buffer held in an
unclaimed completion record, preventing subsequent allocation.

The fix gives each enqueue fresh completion interest, checks handle generation
before cancellation, checks live interest when the radio finishes, and immediately
reclaims completed buffers when their caller leaves. Pending and in-progress
frames continue transmitting when their handle is dropped. The generation counter
does not wrap: after its practically unreachable `u64` limit, enqueue explicitly
panics before mutation. This also avoids silently corrupting ring indices for
non-power-of-two capacities. No extra queue buffers or per-slot fields are added.

Authentication, association, EAPOL handling, retry policy, and the public error
types are unchanged. In particular, a valid peer response remains usable when a
local TX reported a missing ACK. The host tests establish queue ownership and
wakeup behavior; device tests still need to validate the combined radio and
network-stack integration. They do not establish that every connection timeout
or radio packet loss has been resolved.

Validation of this change: all fifteen tests pass with the eight-buffer debug
configuration and three-buffer release configuration. Running the same harness
against the unmodified `cf2415b` queue reproduces eleven failing tests. An
ESP32-C3 `sta_smoke` release build also links with both `foa` and `foa_sta`
resolved to this checkout; that compilation uses dummy credentials and does not
flash hardware.
