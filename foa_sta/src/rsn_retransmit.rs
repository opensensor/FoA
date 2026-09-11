//! Recover a lost M4 without reinstalling keys or resetting data replay state.
use ieee80211::{
    GenericFrame, crypto::deserialize_eapol_data_frame, data_frame::DataFrame,
    elements::kde::GtkKde, mac_parser::MACAddress,
};

use crate::rsn::WPA2_PSK_AKM;

/// State of the completed initial exchange, separate from CCMP packet numbers.
pub(crate) struct Message3Replay {
    authenticator_nonce: [u8; 32],
    pub supplicant_nonce: [u8; 32],
    replay_counter: u64,
}
impl Message3Replay {
    pub fn new(
        authenticator_nonce: [u8; 32],
        supplicant_nonce: [u8; 32],
        replay_counter: u64,
    ) -> Self {
        Self {
            authenticator_nonce,
            supplicant_nonce,
            replay_counter,
        }
    }

    /// Accept only authenticated M3 retries for the already installed keys.
    /// No key-slot or data packet-number state is accessible through this API.
    #[allow(clippy::too_many_arguments)]
    pub fn accept(
        &mut self,
        buffer: &mut [u8],
        scratch: &mut [u8],
        kck: &[u8; 16],
        kek: &[u8; 16],
        gtk: &[u8; 16],
        gtk_id: u8,
        own_address: MACAddress,
        bssid: MACAddress,
    ) -> Option<u64> {
        // ieee80211 0.5.9's EAPOL decoder assumes valid slice lengths in its
        // encrypted-key-data path. Check framing before invoking that decoder.
        let generic = GenericFrame::new(buffer, false).ok()?;
        let frame = generic.parse_to_typed::<DataFrame>()?.ok()?;
        if frame.header.address_1 != own_address
            || frame.header.address_2 != bssid
            || !frame.header.fcf_flags.from_ds()
            || frame.header.fcf_flags.to_ds()
            || frame.header.fcf_flags.protected()
        {
            return None;
        }
        let payload = frame.payload?;
        if payload.get(..8)? != [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e] {
            return None;
        }
        let eapol = payload.get(8..)?;
        if eapol.len() < 99 || eapol[1] != 3 || eapol[4] != 2 {
            return None;
        }
        let body_len = u16::from_be_bytes([eapol[2], eapol[3]]) as usize;
        let key_data_len = u16::from_be_bytes([eapol[97], eapol[98]]) as usize;
        // WPA2-PSK/CCMP M3: version 2, pairwise, install, ACK, MIC, secure,
        // encrypted key data; request/error/reserved key-index bits stay clear.
        if u16::from_be_bytes([eapol[5], eapol[6]]) != 0x13ca
            || u16::from_be_bytes([eapol[7], eapol[8]]) != 16
            || body_len + 4 != eapol.len()
            || key_data_len + 99 != eapol.len()
            || key_data_len < 24
            || key_data_len % 8 != 0
            || key_data_len - 8 > scratch.len()
        {
            return None;
        }
        let key = deserialize_eapol_data_frame(
            Some(kck),
            Some(kek),
            buffer,
            scratch,
            WPA2_PSK_AKM,
            false,
        )
        .ok()?;
        if key.key_nonce != self.authenticator_nonce
            || key.key_replay_counter <= self.replay_counter
        {
            return None;
        }
        let received_gtk = key.key_data.get_first_element::<GtkKde>()?;
        if received_gtk.gtk != gtk || received_gtk.gtk_info.key_id() != gtk_id {
            return None;
        }
        self.replay_counter = key.key_replay_counter;
        Some(self.replay_counter)
    }
}
