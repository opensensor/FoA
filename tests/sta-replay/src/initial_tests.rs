use super::handshake_tests::{m3, m3_with, ready};
use super::*;
use core::marker::PhantomData;
use rsn_initial::InitialHandshake;
use std::{cell::Cell, collections::VecDeque, rc::Rc};

const OWN: MACAddress = MACAddress([2, 0, 0, 0, 0, 1]);
const AP: MACAddress = MACAddress([2, 0, 0, 0, 0, 2]);
const ANONCE: [u8; 32] = [0x31; 32];
const SNONCE: [u8; 32] = [0x32; 32];
const KCK: [u8; 16] = [0; 16];
const KEK: [u8; 16] = [0; 16];

// Independent unencrypted M1 wire fixture: 24-byte 802.11 header, LLC,
// 4-byte EAPOL header, then the 95-byte WPA2 descriptor with no key data.
fn m1(counter: u64) -> Vec<u8> {
    let mut bytes = vec![0; 131];
    bytes[0] = 8;
    bytes[1] = 2;
    bytes[4..10].copy_from_slice(&OWN.0);
    bytes[10..16].copy_from_slice(&AP.0);
    bytes[16..22].copy_from_slice(&AP.0);
    bytes[24..32].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    bytes[32..41].copy_from_slice(&[2, 3, 0, 95, 2, 0, 0x8a, 0, 16]);
    bytes[41..49].copy_from_slice(&counter.to_be_bytes());
    bytes[49..81].copy_from_slice(&ANONCE);
    bytes
}
fn pending() -> InitialHandshake {
    InitialHandshake::from_message_1(&m1(7), OWN, AP).unwrap()
}

#[test]
fn m1_retries_keep_the_exchange_and_allow_equal_or_increasing_counters() {
    let mut state = pending();
    for count in [7, 8, 8, 9] {
        assert_eq!(state.message_1_retry(&m1(count), OWN, AP), Some(count));
        assert_eq!(state.authenticator_nonce, ANONCE);
    }
    assert_eq!(state.message_1_retry(&m1(8), OWN, AP), None);
    let mut changed = m1(99);
    changed[49] ^= 1;
    assert_eq!(state.message_1_retry(&changed, OWN, AP), None);
    assert_eq!(state.replay_counter, 9);
}

#[test]
fn m1_wrong_addresses_flags_and_truncations_are_rejected() {
    let valid = m1(7);
    for length in 0..valid.len() {
        assert!(InitialHandshake::from_message_1(&valid[..length], OWN, AP).is_none());
    }
    for offset in [4, 10, 24, 30, 32, 33, 34, 36, 39, 129] {
        let mut invalid = valid.clone();
        invalid[offset] ^= 0x80;
        assert!(
            InitialHandshake::from_message_1(&invalid, OWN, AP).is_none(),
            "offset {offset}"
        );
    }
    for flags in [0, 1, 3, 0x42] {
        let mut invalid = valid.clone();
        invalid[1] = flags;
        assert!(InitialHandshake::from_message_1(&invalid, OWN, AP).is_none());
    }
    for flags in [0x008b_u16, 0x018a, 0x13ca, 0x048a, 0x088a, 0x208a, 0x0082] {
        let mut invalid = valid.clone();
        invalid[37..39].copy_from_slice(&flags.to_be_bytes());
        assert!(InitialHandshake::from_message_1(&invalid, OWN, AP).is_none());
    }
}

#[test]
fn initial_m3_requires_matching_nonce_new_counter_and_valid_mic_without_poisoning_state() {
    let mut state = pending();
    let mut bad_mic = m3(99);
    bad_mic[113] ^= 1;
    for mut invalid in [m3(6), m3(7), m3_with(99, [4; 32], [0; 16], 1), bad_mic] {
        assert!(
            state
                .message_3(&mut invalid, &mut [0; 512], &KCK, &KEK, OWN, AP)
                .is_none()
        );
        assert_eq!(state.replay_counter, 7);
    }
    let key = state
        .message_3(&mut m3(8), &mut [0; 512], &KCK, &KEK, OWN, AP)
        .unwrap();
    assert_eq!((key.counter, key.gtk, key.gtk_id), (8, [0; 16], 1));
}

#[test]
fn initial_m3_checks_bounds_before_decoding() {
    let valid = m3(8);
    for length in 0..valid.len() {
        assert!(
            pending()
                .message_3(
                    &mut valid[..length].to_vec(),
                    &mut [0; 512],
                    &KCK,
                    &KEK,
                    OWN,
                    AP
                )
                .is_none()
        );
    }
    for offset in [34, 129] {
        for value in [0_u16, 1, 7, 8, 16, 23, 31, 33, 511, 65535] {
            let mut invalid = valid.clone();
            invalid[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
            assert!(
                pending()
                    .message_3(&mut invalid, &mut [0; 512], &KCK, &KEK, OWN, AP)
                    .is_none()
            );
        }
    }
    assert!(
        pending()
            .message_3(&mut valid.clone(), &mut [], &KCK, &KEK, OWN, AP)
            .is_none()
    );
}

// Only RX/TX ownership and transport are mocked. The async production methods
// are extracted verbatim, so tests catch a missing retry call or stale counter.
macro_rules! probe_event {
    ($($arg:tt)*) => {};
}
struct BSS {
    bssid: MACAddress,
}
struct ConnectionParameters {
    own_address: MACAddress,
}
#[derive(Debug, PartialEq)]
enum StaError {
    AckTimeout,
}
struct ConnectionOperation<'foa, 'vif, 'params> {
    connection_parameters: &'params ConnectionParameters,
    router: &'foa StaRxRouterScopedOperation<'foa, 'vif, 'params>,
    sent: RefCell<Vec<(u64, [u8; 16], [u8; 32])>>,
    fail_send: bool,
}
struct StaRxRouterScopedOperation<'a, 'b, 'c> {
    queue: RefCell<VecDeque<Vec<u8>>>,
    borrowed: Rc<Cell<usize>>,
    _lifetime: PhantomData<(&'a (), &'b (), &'c ())>,
}
struct OwnedFrame {
    bytes: Vec<u8>,
    borrowed: Rc<Cell<usize>>,
}
impl OwnedFrame {
    fn mpdu_buffer(&self) -> &[u8] {
        &self.bytes
    }
    fn mpdu_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
impl Drop for OwnedFrame {
    fn drop(&mut self) {
        self.borrowed.set(self.borrowed.get() - 1);
    }
}
impl StaRxRouterScopedOperation<'_, '_, '_> {
    fn new(frames: Vec<Vec<u8>>) -> Self {
        Self {
            queue: RefCell::new(frames.into()),
            borrowed: Rc::new(Cell::new(0)),
            _lifetime: PhantomData,
        }
    }
    async fn receive(&self) -> OwnedFrame {
        let bytes = self
            .queue
            .borrow_mut()
            .pop_front()
            .expect("unexpected extra receive");
        self.borrowed.set(self.borrowed.get() + 1);
        OwnedFrame {
            bytes,
            borrowed: self.borrowed.clone(),
        }
    }
}
struct TxBuffer<'a> {
    bytes: Vec<u8>,
    _lifetime: PhantomData<&'a ()>,
}
impl TxBuffer<'_> {
    fn new() -> Self {
        Self {
            bytes: vec![0; 512],
            _lifetime: PhantomData,
        }
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
impl ConnectionOperation<'_, '_, '_> {
    async fn send_message_2(
        &self,
        _: &BSS,
        kck: &[u8; 16],
        nonce: &[u8; 32],
        counter: u64,
    ) -> Result<(), StaError> {
        assert_eq!(
            self.router.borrowed.get(),
            0,
            "RX frame must be released before TX wait"
        );
        self.sent.borrow_mut().push((counter, *kck, *nonce));
        if self.fail_send {
            Err(StaError::AckTimeout)
        } else {
            Ok(())
        }
    }
}
include!(concat!(env!("OUT_DIR"), "/initial_handlers.rs"));

#[test]
fn actual_initial_wait_loop_resends_m2_with_original_nonce_and_kck_then_accepts_m3() {
    let mut other_nonce = m1(99);
    other_nonce[49] ^= 1;
    let router = StaRxRouterScopedOperation::new(vec![
        vec![0; 8],
        m1(7),
        m1(6),
        other_nonce,
        m1(8),
        m1(8),
        m3(7),
        m3(9),
    ]);
    let params = ConnectionParameters { own_address: OWN };
    let op = ConnectionOperation {
        connection_parameters: &params,
        router: &router,
        sent: RefCell::new(vec![]),
        fail_send: false,
    };
    let bss = BSS { bssid: AP };
    let mut state = ready(op.process_message_1(&router, &bss));
    let gtk = ready(op.process_message_3(
        &router,
        TxBuffer::new(),
        &bss,
        &KCK,
        &KEK,
        &SNONCE,
        &mut state,
    ))
    .unwrap();
    assert_eq!(&*op.sent.borrow(), &[(8, KCK, SNONCE), (8, KCK, SNONCE)]);
    assert_eq!((gtk.key, gtk.key_id, state.replay_counter), ([0; 16], 1, 9));
    assert_eq!(router.borrowed.get(), 0);
}

#[test]
fn actual_wait_loop_propagates_m2_transmit_failure() {
    let router = StaRxRouterScopedOperation::new(vec![m1(8), m3(9)]);
    let params = ConnectionParameters { own_address: OWN };
    let op = ConnectionOperation {
        connection_parameters: &params,
        router: &router,
        sent: RefCell::new(vec![]),
        fail_send: true,
    };
    let bss = BSS { bssid: AP };
    let result = ready(op.process_message_3(
        &router,
        TxBuffer::new(),
        &bss,
        &KCK,
        &KEK,
        &SNONCE,
        &mut pending(),
    ));
    assert!(matches!(result, Err(StaError::AckTimeout)));
    assert_eq!(router.queue.borrow().len(), 1);
    assert_eq!(router.borrowed.get(), 0);
}

#[test]
fn authenticated_m3_with_wrong_gtk_length_cannot_panic_or_commit_state() {
    let mut state = pending();
    for length in [0, 1, 15, 17, 32] {
        let mut frame = super::handshake_tests::m3_with_gtk_bytes(99, ANONCE, &vec![0; length], 1);
        assert!(
            state
                .message_3(&mut frame, &mut [0; 512], &KCK, &KEK, OWN, AP)
                .is_none()
        );
        assert_eq!(state.replay_counter, 7);
    }
    assert!(
        state
            .message_3(&mut m3(8), &mut [0; 512], &KCK, &KEK, OWN, AP)
            .is_some()
    );
}
