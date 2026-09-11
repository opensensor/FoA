# Background management queue across reconnects

`sh tests/run-stale-deauth.sh` uses the production `RxRouter`, station operation
classifier and `ConnectionStateTracker` directly. `build.rs` extracts the actual
`ConnectionRunner::handle_bg_rx` / `handle_deauth` methods with `syn`; it does not
copy their logic into a test implementation. The hardware-owned frame is replaced
by a byte slice with drop accounting, and the tracker uses a minimal BSS identity.
Tests drive the same `signal_state` transitions as station control; they do not
run a real authentication handshake, DMA hardware or the complete runner future.

At the baseline, management traffic can enter Background while disconnected.
The connection runner waits for `Connected` instead of consuming that queue.
Starting and completing a foreground authentication operation does not clear it.
After a same-AP reconnect, a queued deauth passes directly to `handle_deauth` and
returns `Deauthenticated`. Both TA and BSSID can match the current AP, so address
matching alone cannot identify its association of origin. Four retained frames
also retain four RX buffers at the default queue depth; further routing fails
`QueueFull` and drops the new frame.

These are source/host findings. They do not establish the cause of a particular
device disconnect or association failure. A deauth received **after** a new
authentication begins may be a genuine rejection and must not be erased when
the station enters Connected. The diagnostic ingress/dequeue timestamps provide
separate evidence for actual hardware runs.
