use super::handshake_tests::{key_with, ready};
use super::*;
use ieee80211::{
    crypto::CryptoHeader,
    scroll::{Pread, Pwrite},
};

const OWN: MACAddress = MACAddress([2, 0, 0, 0, 0, 1]);
const AP: MACAddress = MACAddress([2, 0, 0, 0, 0, 2]);

fn g1(counter: u64, key: u8, id: u8, rsc: u64) -> Vec<u8> {
    key_with(counter, [0x44; 32], &[key; 16], id, 0x1382, rsc)
}
fn protected(bytes: &[u8], pn: u64) -> Vec<u8> {
    let data = bytes.pread::<DataFrame>(0).unwrap();
    let data = data.crypto_wrap(CryptoHeader::new(pn, 0).unwrap(), MicState::NotPresent);
    let mut out = vec![0; 512];
    let len = out.pwrite(data, 0).unwrap();
    out.truncate(len);
    out
}
fn deliver(sta: &StaTxRx, mut frame: Vec<u8>) {
    assert!(rsn_group::is_key_frame(&frame));
    ready(ConnectionRunner { sta_tx_rx: sta }.handle_eapol_retry(
        ReceivedFrame { bytes: &mut frame },
        &ConnectionInfo {
            own_address: OWN,
            bss: Bss { bssid: AP },
        },
    ));
}

#[test]
fn authenticated_g1_retains_old_key_and_initializes_new_rsc_without_touching_ptk() {
    let routing = RoutingRunner::new();
    let sta = &routing.sta_tx_rx;
    sta.map_crypto_state(|s| {
        assert!(
            s.security_associations
                .group_key(1)
                .unwrap()
                .update_and_validate_replay_counter(80)
        );
        assert!(
            s.security_associations
                .ptksa
                .update_and_validate_replay_counter(90)
        );
        assert_eq!(s.security_associations.ptksa.next_packet_number(), 1);
    });
    let floor = 0x060504030201;
    deliver(sta, protected(&g1(8, 0x51, 2, floor), 91));
    assert_eq!(&*sta.group_replies.borrow(), &[8]);
    sta.map_crypto_state(|s| {
        assert_eq!(s.key_writes, [2]);
        assert_eq!(s.security_associations.active_group_id, 2);
        let old = s.security_associations.group_key(1).unwrap();
        assert_eq!(old.key, [0; 16]);
        assert!(!old.update_and_validate_replay_counter(80));
        assert!(old.update_and_validate_replay_counter(81));
        let new = s.security_associations.group_key(2).unwrap();
        assert!(!new.update_and_validate_replay_counter(floor));
        assert!(new.update_and_validate_replay_counter(floor + 1));
        assert!(
            !s.security_associations
                .ptksa
                .update_and_validate_replay_counter(91)
        );
        assert_eq!(s.security_associations.ptksa.next_packet_number(), 2);
    });
}

#[test]
fn same_key_retries_acknowledge_without_reinstall_or_rsc_reset() {
    let routing = RoutingRunner::new();
    let sta = &routing.sta_tx_rx;
    deliver(sta, g1(8, 0x51, 2, 4));
    sta.map_crypto_state(|s| {
        assert!(
            s.security_associations
                .group_key(2)
                .unwrap()
                .update_and_validate_replay_counter(70)
        )
    });
    deliver(sta, g1(8, 0x51, 2, 4)); // exact replay of the last exchange
    deliver(sta, g1(9, 0x51, 2, 0)); // AP retry with increasing EAPOL counter
    deliver(sta, g1(8, 0x51, 2, 4)); // now stale
    deliver(sta, g1(9, 0x52, 2, 0)); // equal counter, different key
    deliver(sta, g1(10, 0x51, 3, 0)); // existing key at a different ID
    assert_eq!(&*sta.group_replies.borrow(), &[8, 8, 9]);
    sta.map_crypto_state(|s| {
        assert_eq!(s.key_writes, [2]);
        assert_eq!(s.message3_replay.counter(), 9);
        assert!(
            !s.security_associations
                .group_key(2)
                .unwrap()
                .update_and_validate_replay_counter(70)
        );
        assert!(s.security_associations.group_key(3).is_none());
    });
}

#[test]
fn bad_mic_unwrap_lengths_and_envelopes_cannot_install_or_advance_eapol() {
    let routing = RoutingRunner::new();
    let sta = &routing.sta_tx_rx;
    let valid = g1(8, 0x51, 2, 4);
    for n in 0..valid.len() {
        let mut frame = valid[..n].to_vec();
        ready(ConnectionRunner { sta_tx_rx: sta }.handle_eapol_retry(
            ReceivedFrame { bytes: &mut frame },
            &ConnectionInfo {
                own_address: OWN,
                bss: Bss { bssid: AP },
            },
        ));
    }
    for offset in [4, 10, 32 + 81, 32 + 99, 32 + 97, 32 + 2] {
        let mut frame = valid.clone();
        frame[offset] ^= 1;
        deliver(sta, frame);
    }
    deliver(sta, key_with(8, [0; 32], &[1; 15], 2, 0x1382, 0));
    deliver(sta, key_with(8, [0; 32], &[1; 17], 2, 0x1382, 0));
    deliver(sta, g1(8, 0x51, 2, 1u64 << 48));
    assert!(sta.group_replies.borrow().is_empty());
    sta.map_crypto_state(|s| {
        assert!(s.key_writes.is_empty());
        assert_eq!(s.message3_replay.counter(), 7);
    });
    deliver(sta, valid);
    assert_eq!(&*sta.group_replies.borrow(), &[8]);
}

#[test]
fn protected_eapol_requires_fresh_pairwise_pn_and_correct_iv() {
    let routing = RoutingRunner::new();
    let sta = &routing.sta_tx_rx;
    let frame = protected(&g1(8, 0x51, 2, 4), 40);
    deliver(sta, frame.clone());
    deliver(sta, frame.clone());
    let mut bad_id = protected(&g1(9, 0x52, 1, 0), 41);
    bad_id[27] |= 0x40;
    deliver(sta, bad_id);
    let mut reserved = protected(&g1(9, 0x52, 1, 0), 41);
    reserved[26] = 1;
    deliver(sta, reserved);
    assert_eq!(&*sta.group_replies.borrow(), &[8]);
    deliver(sta, protected(&g1(9, 0x52, 1, 0), 41));
    assert_eq!(&*sta.group_replies.borrow(), &[8, 9]);
}

#[test]
fn actual_data_routing_selects_wire_key_id_and_keeps_independent_floors() {
    let mut routing = RoutingRunner::new();
    deliver(&routing.sta_tx_rx, g1(8, 0x51, 2, 10));
    for (id, pn, accepted) in [
        (1, 80, true),
        (2, 10, false),
        (2, 11, true),
        (1, 79, false),
        (2, 11, false),
        (3, 99, false),
        (1, 81, true),
    ] {
        let mut frame = super::tests::mpdu(pn, true, false, false);
        frame[27] = 0x20 | id << 6;
        assert_eq!(
            routing
                .handle_data_rx(frame.pread::<DataFrame>(0).unwrap())
                .is_some(),
            accepted,
            "key {id} PN {pn}"
        );
    }
    assert_eq!(routing.delivered.len(), 3);
}

#[test]
fn protected_transmit_preserves_inner_eapol_and_reserves_ccmp_mic() {
    let plain = g1(8, 0x51, 2, 4);
    let mut tx = vec![0xaa; 512];
    tx[..plain.len()].copy_from_slice(&plain);
    let length = rsn_group::protect_eapol(&mut tx, plain.len(), 0x060504030201).unwrap();
    assert_eq!(length, plain.len() + 16);
    assert_eq!(&tx[24..32], &[1, 2, 0, 0x20, 3, 4, 5, 6]);
    assert_eq!(&tx[32..length - 8], &plain[24..]);
    assert_eq!(&tx[length - 8..length], &[0; 8]);
    assert!(tx[1] & 0x40 != 0);
    // Model the MAC's receive contract: hardware strips the MIC, retaining IV.
    let (normalized, pn) = rsn_group::normalize(&mut tx[..length - 8], OWN, AP).unwrap();
    assert_eq!(pn, Some(0x060504030201));
    assert_eq!(&tx[..normalized], &plain);
    for pn in [0, 1u64 << 48] {
        assert!(rsn_group::protect_eapol(&mut tx, normalized, pn).is_none());
    }
    assert!(rsn_group::protect_eapol(&mut plain.clone(), plain.len(), 1).is_none());
    assert!(rsn_group::protect_eapol(&mut tx, usize::MAX, 1).is_none());
}
