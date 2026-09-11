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

## Authentication responses retained across an association transition

The foreground queue also retains frames when its scoped operation transitions.
The production `ieee80211` 0.5.9 typed management parser checks management frame
class but does not reject an unexpected management subtype. The regression queues
two valid successful authentication responses, consumes the first, transitions to
association, then queues a genuine successful association response. Raw receive
returns the remaining authentication response first. Parsing its body as an
association response produces status `TdlsRejectedAlternativeProvided` (2) and no
AID: authentication's transaction number 2 occupies association's status field.
This reproduces the observed error text without an on-air association rejection;
it establishes a possible mechanism, not the cause of any specific device run.

Authentication and association now use `receive_connection_response`, which checks
the actual scoped operation's production classifier again at dequeue. A stale
response is dropped, releasing its buffer, and the next matching response remains
available. The existing handshake timeout wraps the entire helper, so discarded
responses do not reset its deadline. Matching rejection statuses remain intact;
authentication arriving after the transition still follows normal background
routing. This change neither flushes queues nor changes source-address policy.

With `connection-trace`, discarded frames produce `stage=sta_stale_frame` with
local time, raw RX timestamp, current operation name, and frame type/subtype.
The event contains no addresses, frame body, credentials, or keys.

The follow-up host checks use Embassy's mock time driver to delay polling a full
stale backlog until 9 ms into a 10 ms receive timeout, then verify expiry at the
original 10 ms deadline. They invoke the production helper with the same outer
`WithTimeout` wrapper; they do not simulate radio TX completion. A classifier
compatibility test also preserves an EAPOL data frame behind a stale association
response. The actual EAPOL handshake keeps its existing parse/discard loop.
CI runs the queue/parser suite in debug and release profiles.

## Device observation

The corrected S3 image recorded a queued Authentication frame discarded during
cycle 4 association, then completed all ten reconnect cycles. It returned 200/200
host replies and 196/200 gateway replies; the final gateway assertion failed.
The preceding diagnostic-only and measured-clock runs stopped at association
status 2 in cycles 5 and 4, respectively. The unchanged reviewed C control returned
200/200 in each direction across ten cycles. These observations establish the
stale-frame path on the device and its recovery, while leaving packet loss as a
separate unresolved problem. They do not reconstruct the missing frame from the
earlier failed runs.

The corrected C3 run completed nine traffic cycles with 180/180 replies in each
direction, then timed out during the tenth connection's WPA2 handshake. It
recorded no stale-response events. The timeout and a reason 15 management ingress
are retained in the report; this response-subtype correction does not establish
general reconnect reliability or alter EAPOL processing.

Exact hashes, comparison settings and retained failures are in the
[HAL device report](https://github.com/opensensor/esp-wifi-hal/blob/main/docs/network/CONNECTION-RESPONSE-VALIDATION.md).
