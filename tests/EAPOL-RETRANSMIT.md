# Recovering a lost message 4

The station previously stopped processing pairwise EAPOL frames after its initial
four-way handshake returned. If message 4 did not reach the AP, retransmitted
message 3 frames entered the background queue and were discarded. Local link-up
could therefore be followed by an AP handshake-timeout deauthentication.

A private S3 fault-injection image omitted the first message 4 while reporting
local completion. The recorder observed three additional message-3 headers
(`KeyInformation=0x13ca`) roughly one second apart, all successfully queued.
The AP then deauthenticated with reason 15 and DHCP timed out. With the recovery
handler and the same omission, the S3 completed DHCP and returned 20/20 host and
20/20 gateway pings. The fault hook is absent from the published implementation.
This establishes a specific recovery defect; it does not identify the cause of
every historical handshake timeout or prove that every apparent MAC success
delivered its frame to the AP.

The background handler now verifies an M3 retry against the installed exchange:
the current AP/station addresses, WPA2-PSK/CCMP flags and framing, MIC, authenticator
nonce, strictly increasing EAPOL replay counter, and unchanged GTK/key ID. It then
uses the existing M4 serializer and transmit path. The context contains only the
exchange nonces and EAPOL counter; the retry operation cannot access hardware key
installation or modify data packet-number state. GTK rekeying and new pairwise
handshakes remain separate work. Initial message-1 retries are covered by the
subsequent [M1 recovery change](M1-RECOVERY.md).

`tests/run-sta-replay.sh` compiles the actual retry verifier and extracts the
production background handler. Only the radio buffer/send boundary is replaced.
The tests use synthetic, cryptographically encoded EAPOL frames. They cover valid
retries, stale/equal counters, corrupted MICs, authenticated nonce/key changes,
wrong addresses/direction, truncation, inconsistent lengths and insufficient
scratch space. A handler test verifies both the M4 request and preservation of
pairwise/group RX replay counters and the TX packet number. Run debug and release
profiles. The existing seven data-replay tests remain in the same twelve-test suite.

## Optional bounded recorder

`foa_sta/handshake-probe` enables a single-station diagnostic recorder, disabled
by default. It stores eleven phase timestamps and the latest 64 numeric events
without console output. Recordings contain no keys, nonces, addresses or payloads.
Read the snapshot after disconnect or failure; the example integration prints
summaries there, including detailed events for retries or failures.

Phases are start, PMK start/end, authentication, association, M1 wait, PTK
derivation, M2 send, M3 wait, M4 send and local 4WHS completion. Phase 10 is before
key-slot insertion and is not proof of AP acceptance. Open networks skip WPA2
phases. Times are wrapping low-32-bit microseconds relative to the connection
operation's reset, excluding preceding scanning; `u32::MAX` means unset.
Queue depths are the last sampled foreground/background lengths, not a live
snapshot. The initial depths are also retained as event 9. Incoming EAPOL header
flags are unverified diagnostic metadata; only the retry verifier determines
whether a response is permitted. Event 12 records acceptance/rejection and event
13 the retry transmit result.

The recorder keeps EAPOL and management evidence after local completion, because
this is where the demonstrated failure occurred. It is process-global, overwrites
the previous connection, and is intended for bounded runs with one active station.
The response-queue test suite also checks queue ownership/depth, ring overwrite,
timestamp wrap and retention of post-completion EAPOL events.

At 80 MHz, the first phase trials measured approximately 1.129 seconds of
synchronous PMK derivation per S3 reconnect and 936 ms per C3 reconnect. This
occurs before authentication is transmitted. These measurements identify a
blocking setup cost, not a demonstrated explanation for the later M4 recovery bug.

Device image hashes, all retained successes/failures and normal reconnect trials
are recorded in the [HAL validation report](https://github.com/opensensor/esp-wifi-hal/blob/main/docs/network/EAPOL-RETRANSMIT.md).
