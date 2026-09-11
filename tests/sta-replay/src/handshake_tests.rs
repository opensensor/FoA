use super::*;
use core::marker::PhantomData;
use ieee80211::{
    common::{DataFrameSubtype, FCFFlags},
    crypto::{
        eapol::{EapolKeyFrame, KeyInformation},
        serialize_eapol_data_frame,
    },
    data_frame::header::DataFrameHeader,
    element_chain,
    elements::kde::{GtkInfo, GtkKde},
};
use llc_rs::{EtherType, SnapLlcFrame};
use rsn_retransmit::Message3Replay;

const OWN: MACAddress = MACAddress([2, 0, 0, 0, 0, 1]);
const AP: MACAddress = MACAddress([2, 0, 0, 0, 0, 2]);
const KCK: [u8; 16] = [0; 16];
const KEK: [u8; 16] = [0; 16];
const GTK: [u8; 16] = [0; 16];
const ANONCE: [u8; 32] = [0x31; 32];
const SNONCE: [u8; 32] = [0x32; 32];

fn m3_with(counter: u64, nonce: [u8; 32], gtk: [u8; 16], key_id: u8) -> Vec<u8> {
    let frame = DataFrame {
        header: DataFrameHeader {
            subtype: DataFrameSubtype::Data,
            fcf_flags: FCFFlags::new().with_from_ds(true),
            address_1: OWN,
            address_2: AP,
            address_3: AP,
            ..Default::default()
        },
        payload: Some(SnapLlcFrame {
            oui: [0; 3],
            ether_type: EtherType::Eapol,
            payload: EapolKeyFrame {
                key_information: KeyInformation::from_bits(0x13ca),
                key_length: 16,
                key_replay_counter: counter,
                key_nonce: nonce,
                key_mic: [0u8; 16],
                key_data: element_chain! { GtkKde {
                    gtk_info: GtkInfo::new().with_key_id(key_id), gtk,
                    _phantom: PhantomData,
                } },
                key_iv: 0,
                key_rsc: 0,
                _phantom: PhantomData,
            },
            _phantom: PhantomData,
        }),
        _phantom: PhantomData,
    };
    let mut buffer = vec![0; 512];
    let written =
        serialize_eapol_data_frame(Some(&KCK), Some(&KEK), frame, &mut buffer, &mut [0; 512])
            .unwrap();
    buffer.truncate(written);
    buffer
}
fn m3(counter: u64) -> Vec<u8> {
    m3_with(counter, ANONCE, GTK, 1)
}
fn accept(state: &mut Message3Replay, buffer: &mut [u8]) -> Option<u64> {
    state.accept(buffer, &mut [0; 512], &KCK, &KEK, &GTK, 1, OWN, AP)
}
fn fresh() -> Message3Replay {
    Message3Replay::new(ANONCE, SNONCE, 7)
}

#[test]
fn only_newer_authenticated_m3_retries_advance_the_eapol_counter() {
    let mut state = fresh();
    assert_eq!(accept(&mut state, &mut m3(7)), None);
    assert_eq!(accept(&mut state, &mut m3(6)), None);
    assert_eq!(accept(&mut state, &mut m3(8)), Some(8));
    assert_eq!(accept(&mut state, &mut m3(8)), None);
    assert_eq!(accept(&mut state, &mut m3(9)), Some(9));
}

#[test]
fn tampered_mic_and_authenticated_key_or_nonce_changes_are_rejected() {
    let mut state = fresh();
    let mut bad_mic = m3(99);
    bad_mic[32 + 81] ^= 1;
    for mut invalid in [
        bad_mic,
        m3_with(99, [0x42; 32], GTK, 1),
        m3_with(99, ANONCE, [0x43; 16], 1),
        m3_with(99, ANONCE, GTK, 2),
    ] {
        assert_eq!(accept(&mut state, &mut invalid), None);
    }
    assert_eq!(
        accept(&mut state, &mut m3(8)),
        Some(8),
        "rejected input must not poison the replay counter"
    );
}

#[test]
fn headers_from_another_station_ap_or_direction_cannot_trigger_m4() {
    for offset in [4, 10] {
        let mut frame = m3(8);
        frame[offset] ^= 4;
        assert_eq!(accept(&mut fresh(), &mut frame), None);
    }
    for flags in [0, 1, 3, 0x42] {
        let mut frame = m3(8);
        frame[1] = flags;
        assert_eq!(accept(&mut fresh(), &mut frame), None);
    }
}

#[test]
fn malformed_lengths_and_short_scratch_never_enter_unchecked_decoder_slices() {
    let valid = m3(8);
    for len in 0..valid.len() {
        assert_eq!(accept(&mut fresh(), &mut valid[..len].to_vec()), None);
    }
    for offset in [32 + 2, 32 + 97] {
        for value in [0u16, 1, 7, 8, 16, 23, 24, 31, 33, 511, 512, 65535] {
            let mut frame = valid.clone();
            frame[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
            assert_eq!(accept(&mut fresh(), &mut frame), None);
        }
    }
    let mut state = fresh();
    assert_eq!(
        state.accept(&mut valid.clone(), &mut [], &KCK, &KEK, &GTK, 1, OWN, AP),
        None
    );
    assert_eq!(accept(&mut state, &mut valid.clone()), Some(8));
}

fn ready<F: core::future::Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    match future.as_mut().poll(&mut core::task::Context::from_waker(
        core::task::Waker::noop(),
    )) {
        core::task::Poll::Ready(value) => value,
        core::task::Poll::Pending => panic!("mock buffer/send boundary unexpectedly pending"),
    }
}

#[test]
fn actual_background_handler_replies_without_reinstalling_or_resetting_data_counters() {
    let routing = RoutingRunner::new();
    let sta = &routing.sta_tx_rx;
    sta.map_crypto_state(|state| {
        let sa = &state.security_associations;
        assert!(sa.ptksa.update_and_validate_replay_counter(45));
        assert!(sa.gtksa.update_and_validate_replay_counter(63));
        for n in 1..=5 {
            assert_eq!(sa.ptksa.next_packet_number(), n);
        }
    });
    let runner = ConnectionRunner { sta_tx_rx: sta };
    let info = ConnectionInfo {
        own_address: OWN,
        bss: Bss { bssid: AP },
    };
    ready(runner.handle_eapol_retry(ReceivedFrame { bytes: &mut m3(8) }, &info));
    assert_eq!(&*sta.replies.borrow(), &[(8, KCK, SNONCE)]);
    // A duplicate EAPOL replay counter is ignored by the actual handler too.
    ready(runner.handle_eapol_retry(ReceivedFrame { bytes: &mut m3(8) }, &info));
    assert_eq!(sta.replies.borrow().len(), 1);
    sta.map_crypto_state(|state| {
        let sa = &state.security_associations;
        assert!(!sa.ptksa.update_and_validate_replay_counter(45));
        assert!(!sa.gtksa.update_and_validate_replay_counter(63));
        assert_eq!(sa.ptksa.next_packet_number(), 6);
        assert_eq!(sa.ptksa.key, [0; PTK_LENGTH]);
        assert_eq!(sa.gtksa.key, GTK);
    });
}
