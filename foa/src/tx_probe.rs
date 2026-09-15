//! Opt-in, bounded gateway-echo diagnostics. No packet logging occurs in the TX path.
//!
//! Records survive scope changes and incomplete transmissions. The recorder owns
//! no frame, key, packet number or address; only its active classifier scope holds
//! the gateway address. Classification runs outside the critical section.

use core::cell::RefCell;
use critical_section::Mutex;
use esp_wifi_hal::prelude::TxError;

/// Maximum retained submissions, without overwriting earlier records.
pub const CAPACITY: usize = 64;

/// Identity independent of the reusable TX queue slot and repeated ICMP sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    ordinal: u32,
    slot: usize,
}
impl Tag {
    /// Monotonic identity for this boot.
    pub fn ordinal(self) -> u32 {
        self.ordinal
    }
}

/// Latest boundary actually observed by the recorder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The station runner received the owned MSDU, before buffer allocation.
    Accepted,
    /// The software queue took ownership of the MPDU.
    Queued,
    /// The background runner removed the MPDU for transmission.
    Picked,
    /// The HAL transmission future returned a result.
    Finished,
}

/// Numeric metadata for one submission; no payload or crypto state is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Boot-local submission identity.
    pub tag: Tag,
    /// Application-supplied connection cycle.
    pub cycle: u32,
    /// Owned ICMP echo sequence, 1 through 20.
    pub sequence: u16,
    /// Last observed TX boundary.
    pub phase: Phase,
    /// Actual HAL result. Success contains the retry count; errors have no count.
    pub completion: Option<Result<u8, TxError>>,
    /// Microseconds since boot at MSDU acceptance.
    pub accepted_us: u64,
    /// Microseconds since boot at software queue insertion.
    pub queued_us: Option<u64>,
    /// Microseconds since boot at queue pickup.
    pub picked_us: Option<u64>,
    /// Microseconds since boot at actual HAL completion.
    pub finished_us: Option<u64>,
}
impl Entry {
    const EMPTY: Self = Self {
        tag: Tag {
            ordinal: 0,
            slot: 0,
        },
        cycle: 0,
        sequence: 0,
        phase: Phase::Accepted,
        completion: None,
        accepted_us: 0,
        queued_us: None,
        picked_us: None,
        finished_us: None,
    };
}

/// Recorder limitations are counted instead of hiding or overwriting evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Owned submissions rejected because the fixed store is full.
    pub capacity_rejections: u32,
    /// Exhausted boot-local identities.
    pub tag_exhaustion: u32,
    /// Invalid, stale or out-of-order lifecycle events.
    pub invalid_events: u32,
    /// Classifier scope changed while a packet was being inspected.
    pub scope_changes: u32,
}

struct Recorder<const N: usize> {
    entries: [Entry; N],
    used: usize,
    last_tag: u32,
    counters: Counters,
}
impl<const N: usize> Recorder<N> {
    const fn new() -> Self {
        Self {
            entries: [Entry::EMPTY; N],
            used: 0,
            last_tag: 0,
            counters: Counters {
                capacity_rejections: 0,
                tag_exhaustion: 0,
                invalid_events: 0,
                scope_changes: 0,
            },
        }
    }
    fn invalid(&mut self) {
        self.counters.invalid_events = self.counters.invalid_events.saturating_add(1);
    }
    fn accept(&mut self, cycle: u32, sequence: u16, at: u64) -> Option<Tag> {
        if cycle == 0 || !(1..=20).contains(&sequence) {
            self.invalid();
            return None;
        }
        if self.used == N {
            self.counters.capacity_rejections = self.counters.capacity_rejections.saturating_add(1);
            return None;
        }
        let Some(next) = self.last_tag.checked_add(1) else {
            self.counters.tag_exhaustion = self.counters.tag_exhaustion.saturating_add(1);
            return None;
        };
        let tag = Tag {
            ordinal: next,
            slot: self.used,
        };
        self.entries[self.used] = Entry {
            tag,
            cycle,
            sequence,
            accepted_us: at,
            ..Entry::EMPTY
        };
        self.used += 1;
        self.last_tag = next;
        Some(tag)
    }
    fn index(&mut self, tag: Tag, phase: Phase, at: u64) -> Option<usize> {
        let index = self.entries[..self.used]
            .get(tag.slot)
            .filter(|e| {
                e.tag == tag
                    && e.phase == phase
                    && at >= e.picked_us.or(e.queued_us).unwrap_or(e.accepted_us)
            })
            .map(|_| tag.slot);
        if index.is_none() {
            self.invalid();
        }
        index
    }
    fn queued(&mut self, tag: Tag, at: u64) {
        if let Some(i) = self.index(tag, Phase::Accepted, at) {
            self.entries[i].queued_us = Some(at);
            self.entries[i].phase = Phase::Queued;
        }
    }
    fn picked(&mut self, tag: Tag, at: u64) {
        if let Some(i) = self.index(tag, Phase::Queued, at) {
            self.entries[i].picked_us = Some(at);
            self.entries[i].phase = Phase::Picked;
        }
    }
    fn finished(&mut self, tag: Tag, at: u64, result: Result<u8, TxError>) {
        if let Some(i) = self.index(tag, Phase::Picked, at) {
            self.entries[i].finished_us = Some(at);
            self.entries[i].completion = Some(result);
            self.entries[i].phase = Phase::Finished;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Scope {
    cycle: u32,
    gateway: [u8; 4],
    generation: u64,
}
struct State {
    recorder: Recorder<CAPACITY>,
    scope: Option<Scope>,
    generation: u64,
}
static STATE: Mutex<RefCell<State>> = Mutex::new(RefCell::new(State {
    recorder: Recorder::new(),
    scope: None,
    generation: 0,
}));
fn with_state<T>(f: impl FnOnce(&mut State) -> T) -> T {
    critical_section::with(|cs| f(&mut STATE.borrow(cs).borrow_mut()))
}
fn now() -> u64 {
    embassy_time::Instant::now().as_micros()
}

/// Enable classification for a gateway batch, without clearing previous records.
/// Returns false for invalid cycles or exhausted scope identities.
pub fn arm(cycle: u32, gateway: [u8; 4]) -> bool {
    with_state(|s| {
        let next = s.generation.checked_add(1);
        if cycle == 0 || next.is_none() {
            s.recorder.invalid();
            s.scope = None;
            return false;
        }
        s.generation = next.unwrap();
        s.scope = Some(Scope {
            cycle,
            gateway,
            generation: s.generation,
        });
        true
    })
}
/// Stop accepting new submissions; existing queue records can still complete.
pub fn disarm() {
    with_state(|s| s.scope = None);
}

/// Classify an owned Ethernet MSDU and record its acceptance before MAC wrapping.
/// This classifier does not validate IP/ICMP checksums or claim wire validity.
pub fn accept_msdu(ethernet: &[u8]) -> Option<Tag> {
    let scope = with_state(|s| s.scope)?;
    let sequence = gateway_echo_sequence(ethernet, scope.gateway)?;
    with_state(|s| {
        if s.scope != Some(scope) {
            s.recorder.counters.scope_changes = s.recorder.counters.scope_changes.saturating_add(1);
            return None;
        }
        s.recorder.accept(scope.cycle, sequence, now())
    })
}
pub(crate) fn queued(tag: Tag) {
    with_state(|s| s.recorder.queued(tag, now()));
}
pub(crate) fn picked(tag: Tag) {
    with_state(|s| s.recorder.picked(tag, now()));
}
pub(crate) fn finished(tag: Tag, result: Result<u8, TxError>) {
    with_state(|s| s.recorder.finished(tag, now(), result));
}

/// Number of retained submissions. Records are never cleared during this boot.
pub fn len() -> usize {
    with_state(|s| s.recorder.used)
}
/// Copy one entry under a short lock. Formatting must occur after this returns.
/// Each entry is consistent; separate calls do not form an atomic batch snapshot.
pub fn entry(index: usize) -> Option<Entry> {
    with_state(|s| s.recorder.entries[..s.recorder.used].get(index).copied())
}
/// Copy all limitation counters without formatting inside the critical section.
pub fn counters() -> Counters {
    with_state(|s| s.recorder.counters)
}

fn gateway_echo_sequence(ethernet: &[u8], gateway: [u8; 4]) -> Option<u16> {
    if ethernet.get(12..14)? != [0x08, 0x00] {
        return None;
    }
    let ip = ethernet.get(14..)?;
    let version_ihl = *ip.first()?;
    let header = ((version_ihl & 15) as usize) * 4;
    if version_ihl >> 4 != 4 || header < 20 {
        return None;
    }
    let total = u16::from_be_bytes(ip.get(2..4)?.try_into().ok()?) as usize;
    if total != header + 520 || total > ip.len() {
        return None;
    }
    if *ip.get(9)? != 1 || ip.get(16..20)? != gateway {
        return None;
    }
    let fragment = u16::from_be_bytes(ip.get(6..8)?.try_into().ok()?);
    if fragment & 0x3fff != 0 {
        return None;
    }
    let icmp = ip.get(header..total)?;
    if icmp.get(..2)? != [8, 0] || icmp.get(4..6)? != [0x53, 0x53] {
        return None;
    }
    let sequence = u16::from_be_bytes(icmp.get(6..8)?.try_into().ok()?);
    if !(1..=20).contains(&sequence) || !icmp.get(8..)?.iter().all(|&b| b == 0x5a) {
        return None;
    }
    Some(sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    const GW: [u8; 4] = [10, 0, 0, 1];
    fn packet(ihl: usize, padding: usize) -> Vec<u8> {
        let mut p = vec![0; 14 + ihl + 520 + padding];
        p[12..14].copy_from_slice(&[8, 0]);
        p[14] = 0x40 | (ihl / 4) as u8;
        p[16..18].copy_from_slice(&((ihl + 520) as u16).to_be_bytes());
        p[23] = 1;
        p[30..34].copy_from_slice(&GW);
        let offset = 14 + ihl;
        p[offset] = 8;
        p[offset + 4..offset + 8].copy_from_slice(&[0x53, 0x53, 0, 8]);
        p[offset + 8..offset + 520].fill(0x5a);
        p
    }
    #[test]
    fn owned_shape_with_options_and_padding() {
        for header in (20..=60).step_by(4) {
            for padding in [0, 18] {
                assert_eq!(gateway_echo_sequence(&packet(header, padding), GW), Some(8));
            }
        }
    }
    #[test]
    fn every_truncation_is_rejected() {
        let p = packet(20, 0);
        for n in 0..p.len() {
            assert_eq!(gateway_echo_sequence(&p[..n], GW), None, "length {n}");
        }
    }
    #[test]
    fn unrelated_headers_and_payload_rejected() {
        let base = packet(20, 0);
        for (offset, value) in [
            (12, 0),
            (14, 0x65),
            (14, 0x44),
            (23, 17),
            (30, 11),
            (20, 0x20),
            (21, 1),
            (34, 0),
            (35, 1),
            (38, 0),
            (41, 0),
            (41, 21),
            (42, 0),
        ] {
            let mut p = base.clone();
            p[offset] = value;
            assert_eq!(gateway_echo_sequence(&p, GW), None, "offset {offset}");
        }
    }
    #[test]
    fn dont_validate_or_record_checksums_or_addresses() {
        let mut p = packet(20, 0);
        p[..12].fill(0xa5);
        p[24..26].fill(0xff);
        p[36..38].fill(0xff);
        assert_eq!(gateway_echo_sequence(&p, GW), Some(8));
    }
    #[test]
    fn recorder_retains_failures_and_incomplete_entries() {
        let mut p = Recorder::<3>::new();
        let a = p.accept(1, 8, 10).unwrap();
        p.queued(a, 11);
        p.picked(a, 12);
        p.finished(a, 13, Ok(2));
        let old = p.entries[0];
        p.finished(a, 14, Ok(0));
        assert_eq!(p.entries[0], old);
        let b = p.accept(2, 8, 20).unwrap();
        assert_ne!(a, b);
        p.queued(b, 21);
        assert_eq!(p.entries[1].phase, Phase::Queued);
        assert_eq!(p.entries[1].completion, None);
        let c = p.accept(2, 8, 30).unwrap();
        p.queued(c, 31);
        p.picked(c, 32);
        p.finished(c, 33, Ok(7));
        assert_eq!(p.entries[2].completion, Some(Ok(7)));
        assert_eq!(p.counters.invalid_events, 1);
        assert_eq!(p.accept(3, 1, 40), None);
        assert_eq!(p.counters.capacity_rejections, 1);
        assert_eq!(p.entries[0], old);
    }
    #[test]
    fn invalid_order_and_time_do_not_advance_state() {
        let mut p = Recorder::<1>::new();
        let a = p.accept(1, 1, 10).unwrap();
        p.picked(a, 11);
        p.queued(a, 9);
        p.queued(
            Tag {
                ordinal: 99,
                slot: 0,
            },
            12,
        );
        assert_eq!(p.entries[0].phase, Phase::Accepted);
        assert_eq!(p.counters.invalid_events, 3);
        p.queued(a, 11);
        p.picked(a, 10);
        assert_eq!(p.entries[0].phase, Phase::Queued);
        p.picked(a, 12);
        p.finished(a, 11, Ok(0));
        assert_eq!(p.entries[0].phase, Phase::Picked);
    }
    #[test]
    fn capacity_and_identity_exhaustion_never_overwrite() {
        assert_eq!(Recorder::<0>::new().accept(1, 1, 0), None);
        let mut p = Recorder::<2>::new();
        p.last_tag = u32::MAX - 1;
        assert_eq!(p.accept(1, 1, 0).unwrap().ordinal(), u32::MAX);
        assert_eq!(p.accept(1, 2, 1), None);
        assert_eq!(p.counters.tag_exhaustion, 1);
        assert_eq!(p.used, 1);
    }
    #[test]
    fn invalid_identity_does_not_consume_space() {
        let mut p = Recorder::<1>::new();
        for (c, n) in [(0, 1), (1, 0), (1, 21)] {
            assert_eq!(p.accept(c, n, 0), None);
        }
        assert_eq!(p.used, 0);
        assert_eq!(p.accept(1, 1, 0).unwrap().ordinal(), 1);
    }
}
