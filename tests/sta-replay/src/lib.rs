#![allow(dead_code)]

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

struct CryptoState {
    security_associations: SecurityAssociations,
}
struct StaTxRx {
    crypto_state: RefCell<Option<CryptoState>>,
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
                crypto_state: RefCell::new(Some(CryptoState {
                    security_associations: SecurityAssociations {
                        ptksa: TransientKeySecurityAssociation::new([0; PTK_LENGTH], 0),
                        gtksa: TransientKeySecurityAssociation::new([0; GTK_LENGTH], 1),
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

#[cfg(test)]
mod tests;
