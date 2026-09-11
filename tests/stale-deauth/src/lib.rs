#![allow(dead_code, unexpected_cfgs)]

extern crate self as foa;

use ieee80211::{match_frames, mgmt_frame::{BeaconFrame, DeauthenticationFrame}};
use log::debug;
use std::cell::Cell;

use connection_state::DisconnectionReason;

// The frame bytes and drop accounting replace only the hardware DMA-buffer
// boundary. Routing, queues, operation switching and receive parsing are real.
pub struct ReceivedFrame<'a> {
    bytes: &'a [u8],
    drops: &'a Cell<usize>,
}
impl ReceivedFrame<'_> {
    pub fn mpdu_buffer(&self) -> &[u8] { self.bytes }
    pub fn timestamp(&self) -> u32 { 0 }
}
impl Drop for ReceivedFrame<'_> {
    fn drop(&mut self) { self.drops.set(self.drops.get() + 1); }
}

// The tracker only clones/compares BSS; network discovery is outside this test.
mod bss {
    use ieee80211::mac_parser::MACAddress;
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct BSS { pub bssid: MACAddress }
}
const RX_QUEUE_DEPTH: usize = 4; // foa_sta_config.yml default
struct ConnectionRunner;
include!(concat!(env!("OUT_DIR"), "/production.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use connection_state::{ConnectionConfig, ConnectionInfo, ConnectionState, ConnectionStateTracker};
    use ieee80211::{
        common::{AssociationID, IEEE80211StatusCode}, mac_parser::MACAddress,
        mgmt_frame::{AuthenticationFrame, AssociationResponseFrame}, scroll::Pread,
    };
    use rx_router::{StaRxRouter, StaRxRouterOperation, receive_connection_response};
    use std::{future::Future, pin::pin, task::{Context, Poll, Waker}};
    use util::rx_router::RxRouterRoutingError;

    const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("production future unexpectedly pending"),
        }
    }
    fn pending<F: Future>(future: F) {
        let mut future = pin!(future);
        assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    fn connection() -> ConnectionInfo {
        ConnectionInfo {
            bss: bss::BSS { bssid: MACAddress::new(AP) },
            own_address: MACAddress::new(OWN),
            aid: AssociationID::new_checked(1).unwrap(),
            connection_config: ConnectionConfig { beacon_timeout: None, ..Default::default() },
        }
    }
    fn deauth(sequence: u16) -> [u8; 26] {
        let mut bytes = [0; 26];
        bytes[0] = 0xc0; // unprotected deauthentication
        bytes[4..10].copy_from_slice(&OWN);
        bytes[10..16].copy_from_slice(&AP);
        bytes[16..22].copy_from_slice(&AP);
        bytes[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
        bytes[24] = 3; // leaving network
        bytes
    }
    fn response(subtype: u8, sequence: u16, status: u16) -> [u8; 30] {
        let mut bytes = [0; 30];
        bytes[..24].copy_from_slice(&deauth(sequence)[..24]);
        bytes[0] = subtype;
        if subtype == 0xb0 {
            bytes[26] = 2; // open authentication response
            bytes[28..30].copy_from_slice(&status.to_le_bytes());
        } else {
            bytes[24] = 1; // ESS capabilities
            bytes[26..28].copy_from_slice(&status.to_le_bytes());
            if status == 0 {
                bytes[28..30].copy_from_slice(&0xc001u16.to_le_bytes());
            }
        }
        bytes
    }
    fn disconnected(event: Option<ConnectionRxEvent>) -> DisconnectionReason {
        match event {
            Some(ConnectionRxEvent::Disconnected(reason)) => reason,
            _ => panic!("expected production deauthentication result"),
        }
    }

    #[test]
    fn current_association_deauth_is_the_positive_control() {
        let drops = Cell::new(0);
        let bytes = deauth(100);
        let mut router = StaRxRouter::new();
        let (input, [_foreground, background]) = router.split();
        let state = ConnectionStateTracker::new();
        state.signal_state(ConnectionState::Connected(connection()));
        input.route_frame(ReceivedFrame { bytes: &bytes, drops: &drops }).unwrap();
        let reason = disconnected(ConnectionRunner.handle_bg_rx(ready(background.receive())));
        assert_eq!(reason, DisconnectionReason::Deauthenticated);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn reproduces_stale_deauth_disconnect_after_same_ap_reconnect() {
        let drops = Cell::new(0);
        let bytes = deauth(101);
        let mut router = StaRxRouter::new();
        let (input, [mut foreground, background]) = router.split();
        let state = ConnectionStateTracker::new();
        state.signal_state(ConnectionState::Connected(connection()));
        // Same tracker transition performed by StaControl::disconnect_internal.
        state.signal_state(ConnectionState::Disconnected(DisconnectionReason::User));
        pending(state.wait_for_connection());
        // Delayed prior-association management traffic arrives during the next
        // authentication operation. Production routing sends it to Background.
        let authenticating = ready(foreground.start_operation(StaRxRouterOperation::Authenticating {
            own_address: MACAddress::new(OWN),
        }));
        input.route_frame(ReceivedFrame { bytes: &bytes, drops: &drops }).unwrap();
        pending(authenticating.receive());
        assert_eq!(drops.get(), 0, "background queue retains the old RX buffer");
        authenticating.complete();
        // The production operation boundary does not flush Background. The
        // control path signals Connected when a fresh handshake completes.
        state.signal_state(ConnectionState::Connected(connection()));
        assert_eq!(ready(state.wait_for_connection()), connection());
        let stale = ready(background.receive());
        // Both addresses match the newly associated AP; address validation
        // alone cannot identify this stale frame from the previous association.
        assert_eq!(&stale.mpdu_buffer()[10..16], &AP);
        assert_eq!(&stale.mpdu_buffer()[16..22], &AP);
        let reason = disconnected(ConnectionRunner.handle_bg_rx(stale));
        assert_eq!(reason, DisconnectionReason::Deauthenticated);
        // Same terminal transition used by ConnectionRunner::run.
        state.signal_state(ConnectionState::Disconnected(reason));
        assert_eq!(ready(state.wait_for_disconnection()), DisconnectionReason::Deauthenticated);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn disconnected_background_queue_retains_four_buffers_until_consumed() {
        let drops = Cell::new(0);
        let bytes = deauth(102);
        let mut router = StaRxRouter::new();
        let (input, [_foreground, background]) = router.split();
        let state = ConnectionStateTracker::new();
        pending(state.wait_for_connection());
        for _ in 0..RX_QUEUE_DEPTH {
            input.route_frame(ReceivedFrame { bytes: &bytes, drops: &drops }).unwrap();
        }
        assert_eq!(drops.get(), 0);
        assert!(matches!(input.route_frame(ReceivedFrame { bytes: &bytes, drops: &drops }), Err(RxRouterRoutingError::QueueFull)));
        assert_eq!(drops.get(), 1, "overflow drops only the new frame");
        for _ in 0..RX_QUEUE_DEPTH { drop(ready(background.receive())); }
        assert_eq!(drops.get(), RX_QUEUE_DEPTH + 1);
    }
    #[test]
    fn queued_auth_duplicate_is_reinterpreted_as_association_status_two_without_revalidation() {
        let drops = Cell::new(0);
        let auth = response(0xb0, 201, 0);
        let assoc = response(0x10, 202, 0);
        let mut router = StaRxRouter::new();
        let (input, [mut foreground, _background]) = router.split();
        let mut operation = ready(foreground.start_operation(StaRxRouterOperation::Authenticating {
            own_address: MACAddress::new(OWN),
        }));
        for _ in 0..2 { input.route_frame(ReceivedFrame { bytes: &auth, drops: &drops }).unwrap(); }
        let first = ready(operation.receive());
        assert_eq!(first.mpdu_buffer().pread::<AuthenticationFrame>(0).unwrap().status_code, IEEE80211StatusCode::Success);
        drop(first);
        operation.transition(StaRxRouterOperation::Associating { own_address: MACAddress::new(OWN) }).unwrap();
        input.route_frame(ReceivedFrame { bytes: &assoc, drops: &drops }).unwrap();
        // Production legacy receive and the real parser reproduce the exact
        // observed status without any association rejection on the wire.
        let duplicate = ready(operation.receive());
        let misparsed = duplicate.mpdu_buffer().pread::<AssociationResponseFrame>(0).unwrap();
        assert_eq!(misparsed.status_code, IEEE80211StatusCode::TdlsRejectedAlternativeProvided);
        assert_eq!(misparsed.association_id, None);
        drop(duplicate);
        let genuine = ready(operation.receive());
        assert_eq!(genuine.mpdu_buffer().pread::<AssociationResponseFrame>(0).unwrap().status_code, IEEE80211StatusCode::Success);
    }

    #[test]
    fn current_operation_revalidation_releases_duplicate_and_accepts_association_behind_it() {
        let drops = Cell::new(0);
        let auth = response(0xb0, 203, 0);
        let assoc = response(0x10, 204, 0);
        let mut router = StaRxRouter::new();
        let (input, [mut foreground, _background]) = router.split();
        let mut operation = ready(foreground.start_operation(StaRxRouterOperation::Authenticating {
            own_address: MACAddress::new(OWN),
        }));
        for _ in 0..2 { input.route_frame(ReceivedFrame { bytes: &auth, drops: &drops }).unwrap(); }
        drop(ready(receive_connection_response(&operation)));
        operation.transition(StaRxRouterOperation::Associating { own_address: MACAddress::new(OWN) }).unwrap();
        input.route_frame(ReceivedFrame { bytes: &assoc, drops: &drops }).unwrap();
        let genuine = ready(receive_connection_response(&operation));
        assert_eq!(drops.get(), 2, "first response and stale duplicate released");
        let parsed = genuine.mpdu_buffer().pread::<AssociationResponseFrame>(0).unwrap();
        assert_eq!(parsed.status_code, IEEE80211StatusCode::Success);
        assert_eq!(parsed.association_id, AssociationID::new_checked(1));
        drop(genuine);
        assert_eq!(drops.get(), 3);
    }

    #[test]
    fn current_authentication_and_association_rejection_responses_are_preserved() {
        for (subtype, operation) in [
            (0xb0, StaRxRouterOperation::Authenticating { own_address: MACAddress::new(OWN) }),
            (0x10, StaRxRouterOperation::Associating { own_address: MACAddress::new(OWN) }),
        ] {
            let drops = Cell::new(0);
            let rejection = response(subtype, 205, 2);
            let mut router = StaRxRouter::new();
            let (input, [mut foreground, _background]) = router.split();
            let operation = ready(foreground.start_operation(operation));
            input.route_frame(ReceivedFrame { bytes: &rejection, drops: &drops }).unwrap();
            let received = ready(receive_connection_response(&operation));
            assert_eq!(drops.get(), 0, "a matching response is not discarded based on status");
            let status = if subtype == 0xb0 {
                received.mpdu_buffer().pread::<AuthenticationFrame>(0).unwrap().status_code
            } else {
                received.mpdu_buffer().pread::<AssociationResponseFrame>(0).unwrap().status_code
            };
            assert_eq!(status, IEEE80211StatusCode::TdlsRejectedAlternativeProvided);
        }
    }

    #[test]
    fn authentication_arriving_after_transition_still_routes_to_background() {
        let drops = Cell::new(0);
        let auth = response(0xb0, 206, 0);
        let mut router = StaRxRouter::new();
        let (input, [mut foreground, background]) = router.split();
        let operation = ready(foreground.start_operation(StaRxRouterOperation::Associating {
            own_address: MACAddress::new(OWN),
        }));
        input.route_frame(ReceivedFrame { bytes: &auth, drops: &drops }).unwrap();
        pending(receive_connection_response(&operation));
        assert_eq!(drops.get(), 0);
        drop(ready(background.receive()));
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn filtering_near_deadline_does_not_restart_the_original_timeout() {
        use embassy_time::{Duration, MockDriver, WithTimeout};
        // This is the only test that advances the process-global mock clock.
        let clock = MockDriver::get();
        clock.reset();
        let drops = Cell::new(0);
        let auth = response(0xb0, 207, 0);
        let mut router = StaRxRouter::new();
        let (input, [mut foreground, _background]) = router.split();
        let mut operation = ready(foreground.start_operation(StaRxRouterOperation::Authenticating {
            own_address: MACAddress::new(OWN),
        }));
        for _ in 0..RX_QUEUE_DEPTH {
            input.route_frame(ReceivedFrame { bytes: &auth, drops: &drops }).unwrap();
        }
        operation.transition(StaRxRouterOperation::Associating { own_address: MACAddress::new(OWN) }).unwrap();
        // Match the production call site: one deadline around the entire helper.
        let mut response = pin!(receive_connection_response(&operation).with_timeout(Duration::from_millis(10)));
        // Delay polling until just before that deadline, then discard a whole
        // backlog. Starting a new timeout for each receive would extend to 19ms.
        clock.advance(Duration::from_millis(9));
        assert!(response.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        assert_eq!(drops.get(), RX_QUEUE_DEPTH);
        clock.advance(Duration::from_millis(1));
        assert!(matches!(response.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(_))));
    }

    #[test]
    fn crypto_operation_filter_preserves_eapol_behind_stale_association() {
        let drops = Cell::new(0);
        let assoc = response(0x10, 208, 0);
        let mut eapol = [0u8; 131];
        eapol[..24].copy_from_slice(&deauth(209)[..24]);
        eapol[0] = 0x08; // data, from DS
        eapol[1] = 0x02;
        eapol[24..32].copy_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e]);
        eapol[32..36].copy_from_slice(&[2, 3, 0, 95]); // 802.1X EAPOL-Key header
        eapol[36] = 2; // RSN key descriptor
        eapol[37..39].copy_from_slice(&0x008au16.to_be_bytes()); // pairwise, ACK, MIC version2
        eapol[39..41].copy_from_slice(&16u16.to_be_bytes());
        let mut router = StaRxRouter::new();
        let (input, [mut foreground, _background]) = router.split();
        let mut operation = ready(foreground.start_operation(StaRxRouterOperation::Associating {
            own_address: MACAddress::new(OWN),
        }));
        input.route_frame(ReceivedFrame { bytes: &assoc, drops: &drops }).unwrap();
        operation.transition(StaRxRouterOperation::CryptoHandshake { own_address: MACAddress::new(OWN) }).unwrap();
        input.route_frame(ReceivedFrame { bytes: &eapol, drops: &drops }).unwrap();
        let received = ready(receive_connection_response(&operation));
        assert_eq!(drops.get(), 1);
        assert_eq!(received.mpdu_buffer(), &eapol);
        assert!(ieee80211::GenericFrame::new(received.mpdu_buffer(), false).unwrap().is_eapol_key_frame());
        // Current production EAPOL processing uses its own parse/discard loop;
        // this checks classifier compatibility without changing that path.
    }

}
