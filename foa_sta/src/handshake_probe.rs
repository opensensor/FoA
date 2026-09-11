//! Optional single-station handshake flight recorder. Contains only timings,
//! queue counts and numeric protocol outcomes, never keys or frame payloads.
//! A new connection overwrites the previous snapshot. Not a per-interface API.
use core::cell::RefCell;
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};

/// Phases: start, PMK, PMK done, auth, assoc, M1 wait, PTK, M2 send, M3 wait,
/// M4 send, local 4WHS complete. Times are microseconds relative to reset;
/// MAX means unset. Local completion does not prove AP acceptance of M4.
#[derive(Clone, Copy, Debug, Default)]
#[allow(missing_docs)]
pub struct Event {
    pub us: u32,
    pub phase: u8,
    pub kind: u8,
    pub a: u32,
    pub b: u32,
}

/// Ring records use kind 1=phase, 2=parsed M1, 3=M1 reject, 4=parsed M3,
/// 5=M3 reject, 6=EAPOL route, 7=management route, 8=EAPOL TX outcome,
/// 9=initial queue lengths, 10=received EAPOL-Key header metadata.
/// Reject a: 1=MIC, 2=parse, 3=flags, 4=missing GTK. TX a: 0=success,
/// 1=MAC error, 2=missing completion. Route a is packed kind/queue success;
/// b packs current foreground/background queue depths.
/// Kind 10 a is unverified KeyInformation; b bit 0 is connected, bit 1 retry.
/// Kind 12 a is authenticated M3 retry accepted (1) or rejected (0).
/// Kind 13 a is M4 retry result: 0 success, 1 failed completion.
/// Kind 14 a=1 records a same-exchange M1 retry (unauthenticated).
/// Kind 15 a is its M2 result: 0 success, 1 failed completion.
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct Snapshot {
    pub phase: u8,
    pub phase_us: [u32; 11],
    pub queues: [usize; 2],
    pub eapol_routed: u32,
    pub eapol_dropped: u32,
    pub route_failures: u32,
    pub events: [Event; 64],
    pub total_events: u32,
}
impl Snapshot {
    const fn empty() -> Self {
        Self {
            phase: 0,
            phase_us: [u32::MAX; 11],
            queues: [0; 2],
            eapol_routed: 0,
            eapol_dropped: 0,
            route_failures: 0,
            events: [Event {
                us: 0,
                phase: 0,
                kind: 0,
                a: 0,
                b: 0,
            }; 64],
            total_events: 0,
        }
    }
}
struct State {
    start: u32,
    snapshot: Snapshot,
}
static STATE: Mutex<CriticalSectionRawMutex, RefCell<State>> = Mutex::new(RefCell::new(State {
    start: 0,
    snapshot: Snapshot::empty(),
}));
fn now() -> u32 {
    embassy_time::Instant::now().as_micros() as u32
}
fn append(state: &mut State, now: u32, kind: u8, a: u32, b: u32) {
    let s = &mut state.snapshot;
    s.events[s.total_events as usize % 64] = Event {
        us: now.wrapping_sub(state.start),
        phase: s.phase,
        kind,
        a,
        b,
    };
    s.total_events = s.total_events.wrapping_add(1);
}
/// Clear the recorder before attempting a connection (including scanning).
pub fn reset() {
    let time = now();
    STATE.lock(|s| {
        *s.borrow_mut() = State {
            start: time,
            snapshot: Snapshot::empty(),
        }
    });
}
/// Copy the current counters and ring; call after connection failure or disconnect.
pub fn snapshot() -> Snapshot {
    STATE.lock(|s| s.borrow().snapshot)
}
pub(crate) fn phase(phase: u8) {
    let time = now();
    STATE.lock(|s| {
        let mut s = s.borrow_mut();
        s.snapshot.phase = phase;
        s.snapshot.phase_us[phase as usize] = time.wrapping_sub(s.start);
        append(&mut s, time, 1, phase as u32, 0);
    });
}
pub(crate) fn event(kind: u8, a: u32, b: u32) {
    let time = now();
    STATE.lock(|s| append(&mut s.borrow_mut(), time, kind, a, b));
}
pub(crate) fn routed(kind: u8, success: bool, queues: [usize; 2]) {
    let time = now();
    STATE.lock(|s| {
        let mut s = s.borrow_mut();
        // Keep EAPOL/deauth evidence after local completion: the AP may still
        // be waiting for M4. Ordinary connected traffic does not enter the ring.
        if s.snapshot.phase == 10 && kind == 0 {
            return;
        }
        s.snapshot.queues = queues;
        if !success {
            s.snapshot.route_failures += 1;
        }
        if kind == 1 {
            if success {
                s.snapshot.eapol_routed += 1;
            } else {
                s.snapshot.eapol_dropped += 1;
            }
        }
        if kind != 0 {
            append(
                &mut s,
                time,
                if kind == 1 { 6 } else { 7 },
                ((kind as u32) << 8) | success as u32,
                ((queues[0] as u32) << 16) | queues[1] as u32,
            );
        }
    });
}
