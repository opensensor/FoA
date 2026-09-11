# Reject equal protected-frame packet numbers

The station replay check accepted `received PN == last accepted PN`. A repeated
protected data frame could therefore pass the production routing methods twice
and deliver two MSDUs to the network sink. Change the comparison from `<=` to
`<`: the next accepted PN must be strictly greater. No TX policy, packet number
assignment, logging, raw-frame API, or key-installation behavior changes.

The current completion and IP-boundary traces do not record receive-side CCMP
packet numbers. They do not establish that equal PNs caused any previously
observed duplicate or lost ping. This patch corrects a reproducible acceptance
error; hardware and traffic regression results remain separate evidence.

## Contract and scope

Linux v6.12's
[CCMP receive check](https://github.com/torvalds/linux/blob/v6.12/net/mac80211/wpa.c#L514)
rejects a lower PN or an equal PN without the explicit `RX_FLAG_ALLOW_SAME_PN`
exception. Its
[key allocation](https://github.com/torvalds/linux/blob/v6.12/net/mac80211/key.c#L552)
starts counters at zero, and its
[CCMP transmitter](https://github.com/torvalds/linux/blob/v6.12/net/mac80211/wpa.c#L443)
increments before using the first PN. FoA likewise initializes each receive
counter to zero and its transmit counter to one. PN zero is not a special valid
first frame; PN one passes the corrected check.

FoA keeps separate pairwise and group associations. A completed fresh four-way
handshake constructs new associations and replaces `CryptoState`. The comparator
change neither reinstalls keys nor resets an existing counter.

The payload gate checks one `DataFrame` before software A-MSDU subframe iteration.
It does not run a separate PN check for each subframe. The explicit same-PN
exception for separately delivered pieces of one A-MSDU is not implemented or
needed at that payload-gate boundary.

Existing limits remain:

- FoA's station association does not advertise WMM/QoS, and station TX uses
  non-QoS data. Its current single receive counter per key is not a complete
  implementation for future QoS reception across different TIDs. Linux indexes
  replay state using the
  [received security context](https://github.com/torvalds/linux/blob/v6.12/net/mac80211/rx.c#L831).
- Group-key construction currently ignores the message-3 key RSC. This patch
  does not claim complete GTK replay initialization or rekey support.
- The host A-MSDU test exercises the production **payload gate**, not complete
  over-air A-MSDU support. Current `handle_data_rx` obtains an outer source
  address before reaching this gate; the dependency returns no such address
  for a normal downlink A-MSDU. The dependency also currently serializes and
  parses A-MSDU lengths as little-endian. The test uses that existing
  representation and makes no wire-compliance claim.
- `ieee80211 0.5.9` can panic when `potentially_wrapped_payload` unwraps an invalid
  or truncated CCMP header. This independent parser issue is not repaired here.
- Unprotected-frame duplicate detection, per-TID reorder handling, and hardware
  MIC/duplicate-filter behavior are outside this comparator correction.

## Host regression

```sh
tests/run-sta-replay.sh
tests/run-sta-replay.sh --release
```

The independent host crate uses AST extraction to compile the production
`TransientKeySecurityAssociation` implementation and the production
`process_potentially_wrapped_payload` and `handle_data_rx` methods. It uses the
actual `ieee80211 0.5.9` parser and crypto-header types. Only the state container
and final network-buffer sink are replaced. Input keys, addresses, and payloads
are synthetic. There is no radio, AES operation, or device access in these tests.

Seven tests cover duplicate delivery with either Retry value, first PN zero/one,
unchanged counters after rejection, independent PTK/GTK state, new association
state, A-MSDU payload-gate behavior, and the unchanged unprotected path. The
duplicate test checks the network delivery count, rather than merely comparing
the boolean predicate. All seven pass in debug and release. Running the same
suite against unchanged `c83717e` production sources in a temporary tree with a
separate Cargo target directory produces five failures; the duplicate-delivery
test specifically observes two network deliveries where one is required. The
unprotected-path and new-association tests pass on both versions.

The host crate is kept outside the firmware workspace so the tests require only
the standard Rust host toolchain. CI runs debug and release builds.
