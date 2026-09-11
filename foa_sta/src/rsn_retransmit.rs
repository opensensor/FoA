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
        let key = decrypt_message_3(buffer, scratch, kck, kek, own_address, bssid)?;
        if key.nonce != self.authenticator_nonce || key.counter <= self.replay_counter {
            return None;
        }
        if key.gtk != *gtk || key.gtk_id != gtk_id {
            return None;
        }
        self.replay_counter = key.counter;
        Some(self.replay_counter)
    }
}

/// Check the envelope before the dependency decoder can reach unchecked slices.
pub(crate) fn key_payload(
    buffer: &[u8],
    own_address: MACAddress,
    bssid: MACAddress,
) -> Option<&[u8]> {
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
    if eapol.len() < 99
        || !matches!(eapol[0], 1 | 2)
        || eapol[1] != 3
        || eapol[4] != 2
        || u16::from_be_bytes([eapol[7], eapol[8]]) != 16
    {
        return None;
    }
    let body_len = u16::from_be_bytes([eapol[2], eapol[3]]) as usize;
    let data_len = u16::from_be_bytes([eapol[97], eapol[98]]) as usize;
    if body_len + 4 != eapol.len() || data_len + 99 != eapol.len() {
        return None;
    }
    Some(eapol)
}

pub(crate) struct Message3 {
    pub nonce: [u8; 32],
    pub counter: u64,
    pub gtk: [u8; 16],
    pub gtk_id: u8,
}
pub(crate) fn decrypt_message_3(
    buffer: &mut [u8],
    scratch: &mut [u8],
    kck: &[u8; 16],
    kek: &[u8; 16],
    own_address: MACAddress,
    bssid: MACAddress,
) -> Option<Message3> {
    let eapol = key_payload(buffer, own_address, bssid)?;
    let data_len = eapol.len() - 99;
    // WPA2-PSK/CCMP: pairwise, install, ACK, MIC, secure, encrypted key data.
    if u16::from_be_bytes([eapol[5], eapol[6]]) != 0x13ca
        || data_len < 24
        || data_len % 8 != 0
        || data_len - 8 > scratch.len()
    {
        return None;
    }
    let key =
        deserialize_eapol_data_frame(Some(kck), Some(kek), buffer, scratch, WPA2_PSK_AKM, false)
            .ok()?;
    let gtk = key.key_data.get_first_element::<GtkKde>()?;
    Some(Message3 {
        nonce: key.key_nonce,
        counter: key.key_replay_counter,
        gtk: gtk.gtk.try_into().ok()?,
        gtk_id: gtk.gtk_info.key_id(),
    })
}
