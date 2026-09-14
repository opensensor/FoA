# Unicast EAPOL ACK policy

The shared EAPOL sender explicitly sets `wait_for_ack: true`. Previously it
inherited `false`, so the configured `RetryUntil(7)` policy could not react to
a missing ACK. Ordinary station data already requested ACK waiting.

The production-sender host harness now requires ACK waiting and the seven-retry
policy at MAC submission. The added assertion fails all three sender tests on
the old code and passes with the fix. Existing tests also preserve clear M4,
protected group replies/requests, PN allocation and error/missing-completion
handling. Run `tests/run-sta-replay.sh` in debug and release modes.

C3/S3 paired firmware results, including retained losses, AP rekey retries and
timing limits, are recorded in the [HAL validation report](https://github.com/opensensor/esp-wifi-hal/blob/main/docs/network/EAPOL-ACK-VALIDATION.md).
ACK waiting does not establish AP decryption or EAPOL/application acceptance.
