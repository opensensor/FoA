# Sequence assignment for generated station frames

The ESP32-C3 completion trace exposed station data frames repeatedly completing
with sequence number zero. The station serializer initialized every header with
`SequenceControl::new()`, while its MAC parameters left `override_seq_num` false.
The queue forwards those parameters unchanged. In the HAL,
[`prepare_frame_for_tx`](https://github.com/opensensor/esp-wifi-hal/blob/86db7b111336d56c13aa59eb80a9ac5416ce8854/esp-wifi-hal/src/async_driver.rs#L985)
only assigns a sequence number when that flag is true. This explains the fixed
zero in the completion trace directly.

The station now requests driver assignment at these three transmit sites:

| Generated frame | Transmit site | Change |
| --- | --- | --- |
| Established data, clear or CCMP-protected | `ConnectionRunner::run_msdu_tx` | Enable sequence assignment, retaining the key slot and wait-for-ACK setting. |
| EAPOL key frames, including messages 2 and 4 | `ConnectionOperation::send_eapol_key_frame` | Enable sequence assignment and ACK waiting for the unicast transmission. |
| Authentication and association requests | `ConnectionOperation::do_bidirectional_connection_step` | Enable assignment for each queued request, retaining the existing response/retry loop. |

Deauthentication already enables assignment. Scanning is passive in this tree;
there is no generated probe-request TX path to fix. The public raw-frame endpoint
and `TxMacParameters::default()` retain caller-controlled sequence numbers.
AWDL data is a separate caller with a similar default-parameter site and needs its
own validation; this station correction does not change it.

The driver's counter is read once before its MAC retry loop, so retries of one
queued frame retain the same sequence number. Newly queued requests get a new
number, including an authentication/association request resubmitted after waiting
for a peer response. The 12-bit on-air sequence field wraps normally. No ACK
setting, retry limit, timeout, connection state transition, EAPOL error handling,
or crypto-key operation changes in this patch.

Sequence assignment also occurs at the correct point for the existing crypto
paths. In `ieee80211` 0.5.9, the station's CCMP wrapper serializes the plaintext,
CCMP header, and reserved MIC space; the HAL assigns the sequence before starting
DMA and hardware encryption with the selected key slot. The EAPOL serializer
computes its MIC over EAPOL data after the 802.11 and LLC headers, so replacing the
802.11 sequence field does not alter the authenticated EAPOL bytes.

## Risk and evidence limits

Repeated sequence numbers can defeat duplicate detection. For example,
[Linux mac80211's duplicate check](https://github.com/torvalds/linux/blob/v6.12/net/mac80211/rx.c#L1368)
drops a retried unicast frame when its sequence-control value matches the last
one recorded for that station/sequence context. If a new frame reuses zero and is
then retransmitted, it can resemble an older duplicate. This is a plausible loss
mechanism, not proof that it caused the observed missing gateway reply. The
constant generated sequence is a concrete correctness bug regardless.

At the sequence-fix baseline, the HAL retry loop cleared Retry after the loop
but omitted its update before subsequent attempts. Later history review found
that an async rewrite had removed the old software update. OpenSensor's HAL
now [restores Retry after MAC failures](https://github.com/opensensor/esp-wifi-hal/blob/main/docs/network/MAC-RETRIES.md),
with production-loop regressions and C3/S3 device evidence. That separate fix
does not alter this sequence assignment. The completion trace still reads after
the final clear, so it cannot establish actual on-air Retry values or attribute
all remaining loss to retransmissions.

## Device regression procedure

Use the opt-in completion trace described in [TX-QUEUE.md](TX-QUEUE.md), retaining
the existing packet captures and both successful and failed ping runs.

1. On a fresh boot, connect and run bidirectional pings. In `FOA_TX finish`
   events, verify that newly generated station frames receive advancing sequence
   numbers instead of all completing with zero. Gaps are valid when other
   frames consume the shared driver counter; a first assigned zero is valid.
2. Check authentication, association, EAPOL, and established protected data
   completions. Raw callers that supply their own sequence are outside this
   assertion. Use completion events because start events may still show the
   serializer's placeholder.
3. When `result=Ok(n)` has `n > 0`, correlate that frame with an on-air capture if
   available. Its physical retries should preserve its assigned sequence number;
   the next newly queued frame should get another number. Inspect Retry flags on
   the captured MPDUs independently.
4. Compare unique ping replies, duplicates, and actual completion errors with the
   prior run. Advancing sequence numbers establish this fix; a clean ping run
   alone does not establish the cause of earlier intermittent loss.

The host queue/telemetry regressions remain relevant to completion ownership and
safe diagnostics, but they do not exercise the station task or real hardware
sequence assignment. Firmware cross-linking plus the device trace above are the
validation for this change.

Both ESP32-C3 and ESP32-S3 `sta_smoke` release builds link with this checkout and
completion tracing enabled. That build check uses dummy credentials and does not
flash a device. Subsequent [C3 and S3 hardware traces](https://github.com/opensensor/esp-wifi-hal/blob/main/docs/network/STA-SEQUENCES.md)
verify generated sequence assignment and preserve remaining losses separately.
