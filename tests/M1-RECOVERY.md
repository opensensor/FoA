# Recover a lost M2 during the initial WPA2 handshake

After sending M2, the station previously waited only for M3. A retransmitted M1
was decoded and discarded, so a lost M2 could prevent connection establishment.
The pending exchange now recognizes a matching M1 and sends M2 again using the
same SNonce and KCK and the received EAPOL counter. The RX frame is released
before awaiting TX. The existing connection deadline is not restarted.

The initial M1 and its retries are checked for the selected station/AP,
from-DS direction, unprotected data framing, LLC/EAPOL lengths, WPA2 descriptor,
CCMP key length and exact M1 flags. Retries require the same ANonce and an equal
or increasing counter. M1 has no MIC and remains **unauthenticated**: matching
these fields permits a response, not key installation or AP authentication.
A changed ANonce is a new exchange and is outside this recovery path.

The subsequent M3 uses the bounded parser shared with completed-exchange M3
recovery. It requires a valid MIC, encrypted key data, the pending ANonce, a
counter greater than the most recent M1 and an exactly 16-byte GTK. Invalid
frames do not commit the M3 counter or create a security association. This also
removes the initial path's unchecked GTK-length conversion and protects the
dependency decoder from malformed slice lengths.

The [hostap reference implementation](https://w1.fi/hostapd/devel/src_2rsn__supp_2wpa_8c_source.html)
keeps a supplicant nonce during a pending handshake and sends M2 when processing
M1. Our implementation adds a deliberately narrower retry path for the existing
WPA2-PSK/CCMP exchange; it does not implement the reference's full state machine.

## Validation

The host suite extracts the actual asynchronous initial wait methods and compiles
the production framing/state modules. Only RX/TX transport is mocked. Seven new
tests cover equal/newer M1 retries, stale counters and changed ANonce, malformed
headers/lengths, M3 MIC/nonce/counter checks, invalid GTK lengths, unchanged
M2 nonce/KCK, RX release before TX and propagation of a failed M2 transmission.
Together with existing replay, M3-retry and PSK cases, all 22 tests pass in debug
and release. The ten response/routing/recorder tests also pass in both modes.

A private S3 image omitted its first M2 while reporting local success. The
baseline received and discarded three M1 retries near one, two and three
seconds, then timed out while waiting for M3. With the same omission and this
recovery code, the S3 answered a retry, completed DHCP and returned 20/20 host
and 20/20 gateway echoes. The omission hook is absent from published source.
The [HAL device report](https://github.com/opensensor/esp-wifi-hal/blob/main/docs/network/M1-RECOVERY.md)
retains the failed control, subsequent chip trials and exact image hashes.

Optional recorder kinds 14/15 report a matching M1 retry and its M2 TX result;
they contain no keys, nonce bytes or packet payloads. Initial rejection events
now report generic parse/validation failure; raw-frame dumps are not required.
Existing completed-exchange M3 recovery and data replay tests remain in place.
GTK rekeying and new pairwise exchanges still require separate implementation
and validation. These bounded tests do not establish long-term reliability.
Codex assisted the source investigation, implementation and tests.
