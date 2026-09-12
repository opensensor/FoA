#![allow(dead_code, unexpected_cfgs)]

use core::sync::atomic::Ordering;
use ieee80211::{
    crypto::{MicState, partition_ptk},
    data_frame::{DataFrame, DataFrameReadPayload, PotentiallyWrappedPayload},
    elements::rsn::{IEEE80211AkmType, IEEE80211CipherSuiteSelector},
    mac_parser::MACAddress,
};
use log::{debug, info};
use portable_atomic::AtomicU64;
use std::cell::RefCell;

use rsn_group::GroupMessage1;
struct CryptoState {
    last_group_message: Option<GroupMessage1>,
    key_writes: Vec<u8>,
    security_associations: SecurityAssociations,
    message3_replay: rsn_retransmit::Message3Replay,
}
impl CryptoState {
    fn program_group_key(&mut self, id: u8, _: [u8; 6]) { self.key_writes.push(id); }
}
struct StaTxRx {
    group_replies: RefCell<Vec<u64>>,
    crypto_state: RefCell<Option<CryptoState>>,
    tx_endpoint: MockTxEndpoint,
    replies: RefCell<Vec<(u64, [u8; 16], [u8; 32])>>,
}
impl StaTxRx {
    fn map_crypto_state<O>(&self, f: impl FnOnce(&mut CryptoState) -> O) -> Option<O> {
        self.crypto_state.borrow_mut().as_mut().map(f)
    }
}
struct RoutingRunner {
    sta_tx_rx: StaTxRx,
    delivered: Vec<Vec<u8>>,
}
impl RoutingRunner {
    fn new() -> Self {
        Self {
            sta_tx_rx: StaTxRx {
                tx_endpoint: MockTxEndpoint,
                group_replies: RefCell::new(Vec::new()),
                replies: RefCell::new(Vec::new()),
                crypto_state: RefCell::new(Some(CryptoState {
                    last_group_message: None,
                    key_writes: Vec::new(),
                    message3_replay: rsn_retransmit::Message3Replay::new([0x31; 32], [0x32; 32], 7),
                    security_associations: SecurityAssociations {
                        ptksa: TransientKeySecurityAssociation::new([0; PTK_LENGTH], 0),
                        group_keys: [None, Some(TransientKeySecurityAssociation::new([0; GTK_LENGTH], 1)), None, None],
                        active_group_id: 1,
                        akm_suite: WPA2_PSK_AKM,
                        cipher_suite: IEEE80211CipherSuiteSelector::Ccmp128,
                    },
                })),
            },
            delivered: Vec::new(),
        }
    }
    fn handle_downlink_msdu(&mut self, payload: &[u8], _: MACAddress, _: MACAddress) -> Option<()> {
        // Mock only the final embassy buffer sink. The production method above
        // this boundary selects PTK/GTK, checks PN, and expands A-MSDU payloads.
        self.delivered.push(payload.to_vec());
        Some(())
    }
}

include!(concat!(env!("OUT_DIR"), "/production.rs"));

mod rsn { pub(crate) use super::WPA2_PSK_AKM; }
struct MockTxEndpoint;
impl MockTxEndpoint {
    async fn alloc_tx_buf(&self) -> Vec<u8> { vec![0; 512] }
}
struct ConnectionRunner<'a> { sta_tx_rx: &'a StaTxRx }
struct ReceivedFrame<'a> { bytes: &'a mut [u8] }
impl ReceivedFrame<'_> {
    fn mpdu_buffer_mut(&mut self) -> &mut [u8] { self.bytes }
}
struct Bss { bssid: MACAddress }
struct ConnectionInfo { bss: Bss, own_address: MACAddress }
mod operations {
    pub(crate) mod connect {
        use super::super::*;
        pub(crate) async fn send_group_message_2(sta: &StaTxRx, _: MACAddress, _: MACAddress,
            _: &[u8; 16], counter: u64) -> Result<(), ()> {
            sta.group_replies.borrow_mut().push(counter); Ok(())
        }
        pub(crate) async fn send_message_4(
            sta: &StaTxRx, _: MACAddress, _: MACAddress, kck: &[u8; 16],
            nonce: &[u8; 32], counter: u64,
        ) -> Result<(), ()> {
            sta.replies.borrow_mut().push((counter, *kck, *nonce));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod handshake_tests;
#[cfg(test)]
mod credentials_tests;

#[cfg(test)]
mod initial_tests;

#[cfg(test)]
mod group_tests;
