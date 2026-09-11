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
    use ieee80211::{common::AssociationID, mac_parser::MACAddress};
    use rx_router::{StaRxRouter, StaRxRouterOperation};
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
}
