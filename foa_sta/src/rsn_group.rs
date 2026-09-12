//! Bounded WPA2-PSK/CCMP group-key message decoding and outer EAPOL framing.
use crate::{rsn::WPA2_PSK_AKM, rsn_retransmit::group_key_payload};
use ieee80211::{
    GenericFrame,
    crypto::{MicState, deserialize_eapol_data_frame},
    data_frame::{DataFrame, DataFrameReadPayload, PotentiallyWrappedPayload},
    elements::kde::GtkKde,
    mac_parser::MACAddress,
};

const EAPOL_LLC: [u8; 8] = [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e];

/// Add the CCMP header and MIC space after serializing the inner EAPOL MIC.
/// The radio encrypts the payload using the caller's existing PTK slot.
pub(crate) fn protect_eapol(buffer: &mut [u8], length: usize, pn: u64) -> Option<usize> {
    use ieee80211::{crypto::CryptoHeader, scroll::Pwrite};
    if pn == 0 || pn > CryptoHeader::MAX_PN || length.checked_add(16)? > buffer.len() {
        return None;
    }
    let frame = GenericFrame::new(buffer.get(..length)?, false)
        .ok()?
        .parse_to_typed::<DataFrame>()?
        .ok()?;
    if frame.header.fcf_flags.protected() {
        return None;
    }
    let header = frame.header.length_in_bytes();
    buffer.copy_within(header..length, header + 8);
    buffer.pwrite(CryptoHeader::new(pn, 0)?, header).ok()?;
    buffer[1] |= 0x40;
    buffer[length + 8..length + 16].fill(0);
    Some(length + 16)
}

/// Recognize EAPOL after the MAC's CCMP decryption, without consuming its PN.
/// Classification grants no authority: the connection handler validates the
/// selected AP, direction, EAPOL MIC, key envelope and replay state.
pub(crate) fn is_key_frame(buffer: &[u8]) -> bool {
    let Some(frame) = GenericFrame::new(buffer, false)
        .ok()
        .and_then(|f| f.parse_to_typed::<DataFrame>())
        .and_then(Result::ok)
    else {
        return false;
    };
    let payload = match frame.potentially_wrapped_payload(Some(MicState::NotPresent)) {
        Some(PotentiallyWrappedPayload::Unwrapped(payload)) => payload,
        Some(PotentiallyWrappedPayload::CryptoWrapped(wrapped)) => wrapped.payload,
        None => return false,
    };
    matches!(payload, DataFrameReadPayload::Single(bytes)
        if bytes.get(..8) == Some(&EAPOL_LLC) && bytes.get(9) == Some(&3))
}

/// Remove the hardware-retained CCMP header from an authenticated-key frame
/// envelope. The returned data PN must be checked before any state is changed.
/// The hardware has already checked the CCMP MIC; EAPOL MIC validation follows.
pub(crate) fn normalize(
    buffer: &mut [u8],
    own: MACAddress,
    bssid: MACAddress,
) -> Option<(usize, Option<u64>)> {
    let frame = GenericFrame::new(buffer, false)
        .ok()?
        .parse_to_typed::<DataFrame>()?
        .ok()?;
    if frame.header.address_1 != own
        || frame.header.address_2 != bssid
        || !frame.header.fcf_flags.from_ds()
        || frame.header.fcf_flags.to_ds()
        || !is_key_frame(buffer)
    {
        return None;
    }
    let header_len = frame.header.length_in_bytes();
    let pn = match frame.potentially_wrapped_payload(Some(MicState::NotPresent))? {
        PotentiallyWrappedPayload::Unwrapped(_) => return Some((buffer.len(), None)),
        PotentiallyWrappedPayload::CryptoWrapped(wrapped) => wrapped.crypto_header.packet_number(),
    };
    // CCMP's extended IV flag and pairwise key ID (zero), reserved bits/byte.
    let crypto = buffer.get(header_len..header_len + 8)?;
    if crypto[2] != 0 || crypto[3] != 0x20 {
        return None;
    }
    buffer.copy_within(header_len + 8.., header_len);
    buffer[1] &= !0x40;
    Some((buffer.len() - 8, Some(pn)))
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GroupMessage1 {
    pub counter: u64,
    pub nonce: [u8; 32],
    pub key: [u8; 16],
    pub key_id: u8,
    pub rsc: u64,
}

pub(crate) fn decode_group_message_1(
    buffer: &mut [u8],
    scratch: &mut [u8],
    kck: &[u8; 16],
    kek: &[u8; 16],
    own: MACAddress,
    bssid: MACAddress,
) -> Option<GroupMessage1> {
    let envelope = group_key_payload(buffer, own, bssid)?;
    // Descriptor v2, group, ACK, MIC, secure and encrypted key data.
    if u16::from_be_bytes([envelope[5], envelope[6]]) != 0x1382 {
        return None;
    }
    let data_len = envelope.len() - 99;
    if data_len < 24 || data_len % 8 != 0 || data_len - 8 > scratch.len() {
        return None;
    }
    // CCMP RSC is a 48-bit little-endian packet number on the wire. Do not use
    // the dependency's generic big-endian u64 view for this cipher's counter.
    if envelope[71..73] != [0, 0] {
        return None;
    }
    let mut rsc_bytes = [0; 8];
    rsc_bytes[..6].copy_from_slice(&envelope[65..71]);
    let rsc = u64::from_le_bytes(rsc_bytes);
    let key =
        deserialize_eapol_data_frame(Some(kck), Some(kek), buffer, scratch, WPA2_PSK_AKM, false)
            .ok()?;
    let gtk = key.key_data.get_first_element::<GtkKde>()?;
    Some(GroupMessage1 {
        counter: key.key_replay_counter,
        nonce: key.key_nonce,
        key: gtk.gtk.try_into().ok()?,
        key_id: gtk.gtk_info.key_id(),
        rsc,
    })
}
