# Bounded gateway TX completion probe

Enable `foa_sta/tx-probe` (which enables `foa/tx-probe`) to carry an optional
identity from the station's Ethernet MSDU handoff through queue insertion,
pickup and the HAL transmission result. Ordinary `transmit_edca` callers keep
their existing API and have no tag. The probe does not await a pending handle,
alter ACK/retry policy, change crypto state or add retransmissions.

The application arms a scope with its gateway IPv4 address and connection cycle.
Only the owned ICMP echo shape is classified: identifier `0x5353`, sequence
1..20, 512 bytes of `0x5a`. IPv4 options and Ethernet padding are supported;
fragmented, truncated or unrelated frames are excluded. This is not checksum
validation. Classification occurs before off-channel waits and TX allocation,
outside the recorder's critical section. A scope change during classification
is detected. This opt-in scope is intended for one diagnostic station.

The 64-entry fixed store never overwrites or resets records during a boot. Tags
remain distinct across reconnections and queue reuse. Capacity, identity,
ordering and scope-change limitations are visible in counters. Each stage holds
a monotonic timestamp. Completion stores the actual `Result<u8, TxError>`:
`Ok(n)` is the successful retry count; errors do not contain an attempt count.
No hardware-attempt hook is installed. Queue pickup is not proof of a hardware
start, MAC success is not proof of AP/IP delivery, and an abandoned transmission
remains incomplete rather than acquiring a manufactured result.

The queue records completion before releasing unclaimed results, so discarded
pending handles retain their diagnostic outcome. Buffer ownership and normal
queue wakeups remain unchanged. No frame, address, key or packet number is
stored in an entry. The scope holds only the gateway needed for classification.

Disarm after the measured batch. Copy entries individually and format outside
the lock, before the application's existing loss assertion. Reads are coherent
per entry, not an atomic snapshot of every entry; pending operations can still
complete after disarming. Long runs must account for the fixed capacity. This
implementation adds classifier and short critical-section work: a paired device
comparison is required, and a small latency difference is not a cycle-overhead
measurement.

`tests/run-tx-queue.sh --features tx-probe` compiles the actual production probe,
queue, buffer management, synchronization and clock against a mocked radio
boundary. It covers classification, bounded identity/storage, invalid lifecycle
events, discarded handles retaining errors/retry counts, queue reuse, runner
cancellation and pool recovery. The same suite runs with a three-buffer pool
and release arithmetic. Hardware results are recorded by the HAL examples.
