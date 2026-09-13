//! Compile the production senders and serializer; mock only MAC submission.
use super::*;
use core::marker::PhantomData;
use ieee80211::{
    common::{DataFrameSubtype, FCFFlags, SequenceControl},
    crypto::{
        eapol::{EapolKeyFrame, KeyDescriptorVersion, KeyInformation},
        serialize_eapol_data_frame,
    },
    data_frame::header::DataFrameHeader,
    element_chain,
    scroll::{self, ctx::TryIntoCtx},
};
use llc_rs::{EtherType, SnapLlcFrame};

type StaTxRx<'a, 'b> = super::StaTxRx;
struct ConnectionOperation;
#[derive(Debug, PartialEq, Eq)]
enum StaError {
    AckTimeout,
    TxCompletionLost,
    GroupKeyHandshakeFailure,
}
#[derive(Default)]
struct EdcaAccessCategory;
#[derive(Default)]
struct TxPlcpParameters {
    rate: u8,
    _unused: (),
}
#[derive(Default)]
struct TxMacParameters {
    override_seq_num: bool,
    key_slot_index: Option<u8>,
    _unused: (),
}
enum RetryBehaviour {
    RetryUntil(u8),
}
struct TxReturnData {
    result: Result<(), ()>,
}
struct PendingTx(Option<Result<(), ()>>);
impl PendingTx {
    async fn wait_for_completion(self) -> Option<TxReturnData> {
        self.0.map(|result| TxReturnData { result })
    }
}
impl MockTxEndpoint {
    fn transmit_edca(
        &self,
        _: EdcaAccessCategory,
        mut bytes: Vec<u8>,
        length: usize,
        _: TxPlcpParameters,
        mac: TxMacParameters,
        _: RetryBehaviour,
    ) -> PendingTx {
        bytes.truncate(length);
        assert!(mac.override_seq_num);
        self.transmissions
            .borrow_mut()
            .push((bytes, mac.key_slot_index));
        PendingTx(
            self.completions
                .borrow_mut()
                .pop_front()
                .unwrap_or(Some(Ok(()))),
        )
    }
}
macro_rules! probe_event {
    ($($tt:tt)*) => {};
}
include!(concat!(env!("OUT_DIR"), "/wire_senders.rs"));

#[test]
fn actual_m4_retries_remain_clear_even_with_a_local_ptk_while_group_replies_use_it() {
    use super::handshake_tests::ready;
    let routing = RoutingRunner::new();
    let sta = &routing.sta_tx_rx;
    let own = MACAddress([2, 0, 0, 0, 0, 1]);
    let ap = MACAddress([2, 0, 0, 0, 0, 2]);
    let kck = [0; 16];
    let nonce = [0x32; 32];
    ready(private::send_message_4(sta, ap, own, &kck, &nonce, 8)).unwrap();
    ready(private::send_group_message_2(sta, ap, own, &kck, 9)).unwrap();
    let tx = sta.tx_endpoint.transmissions.borrow();
    let (m4, slot) = &tx[0];
    assert_eq!(*slot, None, "AP can still lack PTK when M4 was lost");
    assert_eq!(m4[1] & 0x40, 0);
    assert_eq!(&m4[37..39], &[3, 0x0a]);
    let (g2, slot) = &tx[1];
    assert_eq!(*slot, Some(4));
    assert_ne!(g2[1] & 0x40, 0);
    assert_eq!(
        &g2[24..32],
        &[1, 0, 0, 0x20, 0, 0, 0, 0],
        "M4 must not consume a PTK PN"
    );
    assert_eq!(&g2[45..47], &[3, 2]);
    assert_eq!(&g2[47..49], &[0, 0]);
    assert_eq!(&g2[57..89], &[0; 32]);
    sta.map_crypto_state(|s| assert_eq!(s.security_associations.ptksa.next_packet_number(), 2));
}

#[test]
fn group_reply_without_established_ptk_is_not_submitted_clear() {
    use super::handshake_tests::ready;
    let routing = RoutingRunner::new();
    let sta = &routing.sta_tx_rx;
    sta.crypto_state.borrow_mut().take();
    let own = MACAddress([2, 0, 0, 0, 0, 1]);
    let ap = MACAddress([2, 0, 0, 0, 0, 2]);
    assert!(ready(private::send_group_message_2(sta, ap, own, &[0; 16], 9)).is_err());
    assert!(ready(private::send_group_request(sta, ap, own, &[0; 16], 10)).is_err());
    assert!(sta.tx_endpoint.transmissions.borrow().is_empty());
    ready(private::send_message_4(sta, ap, own, &[0; 16], &[0; 32], 8)).unwrap();
    assert_eq!(sta.tx_endpoint.transmissions.borrow()[0].1, None);
}

#[test]
fn actual_eapol_senders_require_a_successful_completion() {
    use super::handshake_tests::ready;
    let own = MACAddress([2, 0, 0, 0, 0, 1]);
    let ap = MACAddress([2, 0, 0, 0, 0, 2]);
    for kind in 0..3 {
        for completion in [Some(Ok(())), Some(Err(())), None] {
            let routing = RoutingRunner::new();
            let sta = &routing.sta_tx_rx;
            sta.tx_endpoint
                .completions
                .borrow_mut()
                .push_back(completion);
            let result = match kind {
                0 => ready(private::send_message_4(sta, ap, own, &[0; 16], &[0; 32], 8)),
                1 => ready(private::send_group_message_2(sta, ap, own, &[0; 16], 9)),
                2 => ready(private::send_group_request(sta, ap, own, &[0; 16], 10)),
                _ => unreachable!(),
            };
            let expected = match completion {
                Some(Ok(())) => Ok(()),
                Some(Err(())) => Err(StaError::AckTimeout),
                None => Err(StaError::TxCompletionLost),
            };
            assert_eq!(result, expected, "sender {kind}, completion {completion:?}");
            assert!(sta.tx_endpoint.completions.borrow().is_empty());
            let tx = sta.tx_endpoint.transmissions.borrow();
            assert_eq!(
                tx.len(),
                1,
                "Completion failure must not resubmit the protected frame"
            );
            let (frame, slot) = &tx[0];
            if kind == 0 {
                assert_eq!(*slot, None);
                assert_eq!(frame[1] & 0x40, 0);
                assert_eq!(&frame[37..39], &[3, 0x0a]);
            } else {
                assert_eq!(*slot, Some(4));
                assert_ne!(frame[1] & 0x40, 0);
                assert_eq!(&frame[24..32], &[1, 0, 0, 0x20, 0, 0, 0, 0]);
                assert_eq!(&frame[45..47], if kind == 1 { &[3, 2] } else { &[0x0b, 2] });
            }
            sta.map_crypto_state(|state| {
                assert_eq!(
                    state.security_associations.ptksa.next_packet_number(),
                    if kind == 0 { 1 } else { 2 },
                    "One protected submission consumes exactly one PN"
                );
            });
        }
    }
}
