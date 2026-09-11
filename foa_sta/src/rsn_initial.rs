//! Pending WPA2-PSK exchange. No installed keys or data packet counters live here.
use crate::rsn_retransmit::{Message3, decrypt_message_3, key_payload};
use ieee80211::mac_parser::MACAddress;

pub(crate) struct InitialHandshake {
    pub authenticator_nonce: [u8; 32],
    pub replay_counter: u64,
}
impl InitialHandshake {
    pub fn from_message_1(buffer: &[u8], own: MACAddress, bssid: MACAddress) -> Option<Self> {
        let key = key_payload(buffer, own, bssid)?;
        // M1 has no MIC and is unauthenticated; it may request only an M2 reply.
        if u16::from_be_bytes([key[5], key[6]]) != 0x008a {
            return None;
        }
        Some(Self {
            authenticator_nonce: key[17..49].try_into().ok()?,
            replay_counter: u64::from_be_bytes(key[9..17].try_into().ok()?),
        })
    }

    pub fn message_1_retry(
        &mut self,
        buffer: &[u8],
        own: MACAddress,
        bssid: MACAddress,
    ) -> Option<u64> {
        let retry = Self::from_message_1(buffer, own, bssid)?;
        // Equal counters permit retransmission of an identical M1. A different
        // ANonce is a new exchange, outside this same-exchange recovery path.
        if retry.authenticator_nonce != self.authenticator_nonce
            || retry.replay_counter < self.replay_counter
        {
            return None;
        }
        self.replay_counter = retry.replay_counter;
        Some(self.replay_counter)
    }

    pub fn message_3(
        &mut self,
        buffer: &mut [u8],
        scratch: &mut [u8],
        kck: &[u8; 16],
        kek: &[u8; 16],
        own: MACAddress,
        bssid: MACAddress,
    ) -> Option<Message3> {
        let key = decrypt_message_3(buffer, scratch, kck, kek, own, bssid)?;
        if key.nonce != self.authenticator_nonce || key.counter <= self.replay_counter {
            return None;
        }
        // Advance only after MIC, nonce, lengths and GTK validation succeed.
        self.replay_counter = key.counter;
        Some(key)
    }
}
