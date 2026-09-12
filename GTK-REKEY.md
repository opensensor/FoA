# WPA2-PSK/CCMP group-key rotation

`foa_sta` now handles the two-message group-key exchange while connected. It
authenticates G1, installs the new GTK, and sends G2 using the existing PTK.
Protected EAPOL is classified after the MAC-retained CCMP header. Initial
pairwise handshake messages retain their original clear transmit path until
the PTK exists.

The receive path selects a GTK and replay floor by the **wire key ID**. It
retains old and new IDs through the AP's transition. An `ieee80211` 0.5.9 key-ID
decode shift bug requires reading those two bits directly; the surrounding
CCMP reserved bits and extended-IV flag are checked too.

Authenticated G1 uses the AP's EAPOL counter and a cipher-specific 48-bit,
little-endian Key RSC. Group Key Length zero and legacy CCMP length 16 are
accepted; initial pairwise messages still require length 16. A retry with an
already installed key does not program hardware again or reset its receive
floor. Exact retransmission of the most recent G1 can be acknowledged again;
older counters, changed contents at the same counter, and moving an existing
key to a different ID are rejected. PTK data counters are retained. Hardware
still performs CCMP decryption and MIC checking; software checks the EAPOL MIC
and wrapped key data before installing a GTK.

Each WPA2 connection reserves five hardware slots: one PTK and four GTK IDs.
Slots are released with the connection. This work covers WPA2-PSK/CCMP, not
WPA3, PMF, TKIP, or an AP-initiated pairwise-key replacement.

## Validation

The host harness extracts the production decoder, key-install policy, routing
and connected EAPOL handler. Only radio key writes, TX completion and the final
network sink are mocked. Twenty-eight debug/release tests cover initial and
retried handshakes, group transitions, replay floors, malformed envelopes,
wrong MICs, key reuse, protected framing and data delivery under old/new IDs.
The ten existing response/reconnect tests also pass.

```sh
sh tests/run-sta-replay.sh
sh tests/run-sta-replay.sh --release
sh tests/run-stale-deauth.sh
```

The hardware exercise and numeric results are maintained in the
[HAL GTK validation report](https://github.com/opensensor/esp-wifi-hal/blob/main/docs/network/GTK-REKEY.md).
It uses router-originated traffic so the host's separate 6-GHz link is outside
the measured echo path. Raw captures, credentials and signing material remain
private. Short successful rekey trials do not establish indefinite reliability.

## Opt-in hardware probe

The `handshake-probe` feature exposes `StaControl::request_group_rekey()`.
It sends a MIC-authenticated, PTK-protected EAPOL-Key Request. Its request
counter is separate from AP replay counters. A request can rotate the key for
**every station in the BSS**. Normal connection handling never calls it.
No hostapd configuration change or test-only router command is required.

`gtk-rekey-probe` additionally enables numeric group key-ID/PN receive tracing.
The HAL example explicitly opts into requests and labeled broadcast/multicast
traffic; ordinary `sta_smoke` builds retain their existing behavior.
