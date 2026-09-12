use super::*;
use core::marker::PhantomData;
use ieee80211::{
    common::{DataFrameSubtype, FCFFlags},
    crypto::CryptoHeader,
    data_frame::header::DataFrameHeader,
    scroll::{Pread, Pwrite},
};

pub(super) fn mpdu(pn: u64, group: bool, retry: bool, amsdu: bool) -> Vec<u8> {
    let mut payload = Vec::new();
    if amsdu {
        // Two complete software-deaggregated subframes in one protected MPDU.
        for byte in [0x41, 0x42] {
            payload.extend([2, 0, 0, 0, 0, 1]);
            payload.extend([2, 0, 0, 0, 0, 2]);
            // Match ieee80211 0.5.9's current little-endian subframe
            // representation. This exercises the payload gate, not wire ABI.
            payload.extend([2, 0]);
            payload.extend([byte, byte]);
        }
    } else {
        payload.extend(b"synthetic-network-payload");
    }
    let data = DataFrame {
        header: DataFrameHeader {
            subtype: if amsdu {
                DataFrameSubtype::QoSData
            } else {
                DataFrameSubtype::Data
            },
            fcf_flags: FCFFlags::new().with_from_ds(true).with_retry(retry),
            address_1: MACAddress(if group { [0xff; 6] } else { [2, 0, 0, 0, 0, 1] }),
            address_2: MACAddress([2, 0, 0, 0, 0, 2]),
            address_3: MACAddress([2, 0, 0, 0, 0, 3]),
            qos: amsdu.then_some([0x80, 0]),
            ..Default::default()
        },
        payload: Some(payload.as_slice()),
        _phantom: PhantomData,
    }
    .crypto_wrap(
        CryptoHeader::new(pn, u8::from(group)).unwrap(),
        MicState::NotPresent,
    );
    let mut encoded = vec![0; 512];
    let len = encoded.pwrite(data, 0).unwrap();
    encoded.truncate(len);
    encoded
}

fn receive(runner: &mut RoutingRunner, bytes: &[u8]) -> Option<()> {
    runner.handle_data_rx(bytes.pread::<DataFrame<'_, &[u8]>>(0).unwrap())
}

#[test]
fn repeated_protected_frame_reaches_network_once_for_either_retry_flag() {
    for retry in [false, true] {
        let mut runner = RoutingRunner::new();
        assert_eq!(
            receive(&mut runner, &mpdu(1, false, false, false)),
            Some(())
        );
        receive(&mut runner, &mpdu(1, false, retry, false));
        assert_eq!(
            runner.delivered.len(),
            1,
            "equal PN must not deliver a second MSDU"
        );
    }
}

#[test]
fn zero_is_not_a_new_packet_and_first_pn_one_is_accepted() {
    let association = TransientKeySecurityAssociation::<16, false>::new([0; 16], 1);
    assert!(!association.update_and_validate_replay_counter(0));
    assert!(association.update_and_validate_replay_counter(1));
    assert!(!association.update_and_validate_replay_counter(1));
    assert_eq!(association.next_packet_number(), 1);
    assert_eq!(association.next_packet_number(), 2);
}

#[test]
fn equal_and_lower_rejections_do_not_advance_or_reset_the_counter() {
    let association = TransientKeySecurityAssociation::<16, true>::new([0; 16], 0);
    assert!(association.update_and_validate_replay_counter(100));
    assert!(!association.update_and_validate_replay_counter(100));
    assert!(!association.update_and_validate_replay_counter(99));
    assert_eq!(association.replay_counter.load(Ordering::Relaxed), 100);
    assert!(association.update_and_validate_replay_counter(101));
}

#[test]
fn group_and_pairwise_replay_counters_are_independent() {
    let mut runner = RoutingRunner::new();
    assert_eq!(
        receive(&mut runner, &mpdu(100, false, false, false)),
        Some(())
    );
    assert_eq!(receive(&mut runner, &mpdu(1, true, false, false)), Some(()));
    assert_eq!(receive(&mut runner, &mpdu(1, true, true, false)), None);
    assert_eq!(
        receive(&mut runner, &mpdu(101, false, false, false)),
        Some(())
    );
    assert_eq!(runner.delivered.len(), 3);
}

#[test]
fn one_amsdu_payload_gate_preserves_all_subframes() {
    let runner = RoutingRunner::new();
    let bytes = mpdu(1, false, false, true);
    let data = bytes.pread::<DataFrame<'_, &[u8]>>(0).unwrap();
    let wrapped = data
        .potentially_wrapped_payload(Some(MicState::NotPresent))
        .unwrap();
    let Some(DataFrameReadPayload::AMSDU(frames)) =
        runner.process_potentially_wrapped_payload(false, 0, wrapped)
    else {
        panic!("first aggregate must pass the payload gate");
    };
    assert_eq!(
        frames
            .map(|frame| frame.payload.to_vec())
            .collect::<Vec<_>>(),
        [vec![0x41; 2], vec![0x42; 2]]
    );
    assert!(
        runner
            .process_potentially_wrapped_payload(false, 0, wrapped)
            .is_none()
    );
}

#[test]
fn new_association_gets_its_own_fresh_counter() {
    let old = TransientKeySecurityAssociation::<16, true>::new([0; 16], 0);
    assert!(old.update_and_validate_replay_counter(500));
    let new = TransientKeySecurityAssociation::<16, true>::new([1; 16], 0);
    assert!(new.update_and_validate_replay_counter(1));
    assert!(!old.update_and_validate_replay_counter(1));
}

#[test]
fn unprotected_data_path_is_unchanged() {
    let mut runner = RoutingRunner::new();
    let mut bytes = mpdu(0, false, false, false);
    bytes[1] &= !0x40;
    assert_eq!(receive(&mut runner, &bytes), Some(()));
    assert_eq!(receive(&mut runner, &bytes), Some(()));
    assert_eq!(runner.delivered.len(), 2);
}
