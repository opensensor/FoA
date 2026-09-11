# Station connection diagnostics

Enable the optional `foa_sta/connection-trace` feature with `foa_sta=info` in
the log filter to record connection transitions and deauthentication handling.
The feature is off by default and uses the `log` backend. It does not enable
the handshake debug messages or change routing, disconnect or retry policy.

- `stage=sta_mgmt_rx` records deauthentication (subtype12) and disassociation
  (subtype10) immediately before routing: monotonic handling time, hardware RX
  timestamp, reason, sequence/fragment, Retry/Protected bits, connection state,
  foreground operation and address-match booleans. It prints no actual address,
  SSID, key or frame payload.
- `stage=sta_mgmt_route` records whether the same RX timestamp was queued.
- `stage=sta_deauth` records the timestamp again when the connection task consumes
  it. Correlate ingress, dequeue and intervening link transitions to distinguish
  a delayed background frame from a newly received one. Hardware timestamps are
  32-bit values; interpret them within the same short capture and include the
  sequence/fragment fields when correlating.
- `stage=sta_link` records link-up configuration or the cause leading to link
  teardown: user, beacon timeout or deauthentication. Timeout0 means the optional
  beacon timeout is disabled in the smoke configuration. The automatic-reconnect
  value is the configured flag, not proof that a reconnect was attempted.

Address matches are observations, not authentication or newly enforced filters.
Disassociation is traced at ingress but its existing handling is unchanged.
Frames rejected before the RX router are outside these ingress events.
Successful MAC TX completion and queue insertion do not establish delivery to
the host. Keep ARP/ICMP boundary traces and capture-drop counts when investigating
packet losses; the existing smoltcp trace reports pending-response evictions.

Validation includes C3/S3 full application cross-links and the existing replay
and routing regressions. Device observations are recorded with the consuming
OpenSensor HAL examples; trace timing is part of the comparison configuration.
