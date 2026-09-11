# Prepare a PSK once for repeated connections

`Credentials::derive_psk(ssid)` exposes the existing WPA2 passphrase derivation
as a synchronous preparation step. It returns a 32-byte key for the existing
`Credentials::PreSharedKey` input. A raw PSK is copied only if its length is
exactly 32 bytes. This adds no global cache or credential retention policy.

An application using a fixed network can derive the PSK before starting its
radio tasks and reuse it when reconnecting:

```rust,ignore
let psk = Credentials::Passphrase(passphrase).derive_psk(ssid)?;
// Initialize the radio and station here, then reconnect as needed.
control.connect_by_ssid(ssid, None, Some(Credentials::PreSharedKey(&psk))).await?;
```

Keep the returned bytes private. If the SSID or passphrase changes, derive a new
key. `PreSharedKey` is a raw-key API and does not bind itself to an SSID. This
preparation does not cache session keys: each connection still runs the normal
four-way handshake, generates a fresh supplicant nonce and creates its own
pairwise/group key state and packet counters.

The derivation algorithm and work factor are unchanged: the production
`ieee80211` 0.5.9 helper uses PBKDF2-HMAC-SHA1 with 4096 iterations. Calling
`Credentials::Passphrase` directly during every connection still performs that
synchronous work each time. Preparation moves one calculation before the radio
starts and avoids repeating it; it does not make PBKDF2 itself faster or async.

The host replay suite extracts the actual `Credentials` types and implementation
from `bss.rs`. Three additional tests cover an independently checked 32-byte WPA2
vector, repeated use through the connection's raw-PSK path, changed credentials
or SSID, and wrong raw-key lengths. All fifteen tests pass in debug and release.

The HAL station example uses this API and records the once-only preparation cost
separately from each connection's PMK phase. Its device results belong in the
[HAL report](https://github.com/opensensor/esp-wifi-hal/blob/main/docs/network/PSK-PREPARATION.md).
Codex assisted the implementation and test work; the cryptographic primitive
remains the existing dependency implementation.
