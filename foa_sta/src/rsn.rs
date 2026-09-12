use core::sync::atomic::Ordering;

use foa::{
    KeySlot,
    esp_wifi_hal::prelude::{AesCipherParameters, CipherParameters, KeyType, MultiLengthKey},
};
use ieee80211::{
    crypto::partition_ptk,
    elements::rsn::{IEEE80211AkmType, IEEE80211CipherSuiteSelector},
};
use portable_atomic::AtomicU64;

use crate::rsn_group::GroupMessage1;

/// The length of a Pairwise Master Key.
///
/// This is different for two AKMs, which we're luckily very far from implementing.
pub const PMK_LENGTH: usize = 32;
pub const WPA2_PSK_AKM: IEEE80211AkmType = IEEE80211AkmType::Psk;
pub const PTK_LENGTH: usize = WPA2_PSK_AKM.kck_len().unwrap()
    + WPA2_PSK_AKM.kek_len().unwrap()
    + IEEE80211CipherSuiteSelector::Ccmp128.tk_len().unwrap();
pub const GTK_LENGTH: usize = IEEE80211CipherSuiteSelector::Ccmp128.tk_len().unwrap();

#[derive(Debug)]
/// A transient key security association.
///
/// Currently this is only meant for GTKSA's and PTKSA's
pub(crate) struct TransientKeySecurityAssociation<const N: usize, const IS_PAIRWISE: bool> {
    /// The cryptographic key of this TKSA.
    pub key: [u8; N],
    /// The ID of the key.
    pub key_id: u8,
    /// The replay counter tracks the last packet number received from the STA, with which this
    /// TKSA is established. It's updated with the PN of any received frame, where the PN is larger
    /// than the current value.
    replay_counter: AtomicU64,
    /// The TX packet number is incremented by one for every transmitted encapsulated MPDU.
    packet_number: AtomicU64,
}
impl<const N: usize, const IS_PAIRWISE: bool> TransientKeySecurityAssociation<N, IS_PAIRWISE> {
    /// Create a new TKSA with all counters initialized to zero.
    pub const fn new(key: [u8; N], key_id: u8) -> Self {
        Self {
            key,
            key_id,
            replay_counter: AtomicU64::new(0),
            packet_number: AtomicU64::new(1),
        }
    }
    /// Initialize a newly authenticated group key's receive floor from Key RSC.
    pub fn with_receive_floor(self, floor: u64) -> Self {
        self.replay_counter.store(floor, Ordering::Relaxed);
        self
    }
    /// Get the temporal key for this TKSA.
    pub fn tk(
        &self,
        akm_suite: IEEE80211AkmType,
        cipher_suite: IEEE80211CipherSuiteSelector,
    ) -> &[u8] {
        if IS_PAIRWISE {
            partition_ptk(&self.key, akm_suite, cipher_suite).unwrap().2
        } else {
            self.key.as_slice()
        }
    }
    /// Get the next TX packet number for this TKSA.
    pub fn next_packet_number(&self) -> u64 {
        self.packet_number.fetch_add(1, Ordering::Relaxed)
    }
    /// Check if the PN is valid and update the replay counter.
    ///
    /// This will only update the replay counter, if the PN is larger than the current value.
    pub fn update_and_validate_replay_counter(&self, packet_number: u64) -> bool {
        let replay_counter = self.replay_counter.load(Ordering::Relaxed);
        let valid = replay_counter < packet_number;
        if valid {
            self.replay_counter.store(packet_number, Ordering::Relaxed);
        } else {
            debug!(
                "Packet number not greater than replay counter. {} <= {}",
                replay_counter, packet_number
            );
        }
        valid
    }
}
#[derive(Debug)]
/// All security associations used in a WPA2 network.
pub(crate) struct SecurityAssociations {
    /// The pairwise transient key.
    pub ptksa: TransientKeySecurityAssociation<PTK_LENGTH, true>,
    /// Retain both old and new GTK IDs while the AP changes its transmit key.
    pub group_keys: [Option<TransientKeySecurityAssociation<GTK_LENGTH, false>>; 4],
    pub active_group_id: u8,
    /// The Authentication and Key Management Suite.
    pub akm_suite: IEEE80211AkmType,
    /// The cipher suite.
    pub cipher_suite: IEEE80211CipherSuiteSelector,
}
impl SecurityAssociations {
    pub fn pairwise_temporal_key(&self) -> &[u8] {
        self.ptksa.tk(self.akm_suite, self.cipher_suite)
    }
    pub fn group_key(&self, id: u8) -> Option<&TransientKeySecurityAssociation<GTK_LENGTH, false>> {
        self.group_keys.get(id as usize)?.as_ref()
    }
    pub fn active_group_key(&self) -> &TransientKeySecurityAssociation<GTK_LENGTH, false> {
        self.group_key(self.active_group_id).unwrap()
    }
}
/// State of cryptographic management.
pub(crate) struct CryptoState<'foa> {
    /// Authenticated initial-exchange context, independent of data PN state.
    pub message3_replay: crate::rsn_retransmit::Message3Replay,
    /// One hardware slot per GTK ID; rotation does not overwrite the old ID.
    pub gtk_key_slots: [KeySlot<'foa>; 4],
    pub last_group_message: Option<GroupMessage1>,
    #[cfg(feature = "handshake-probe")]
    pub group_request_counter: u64,
    /// Key slot used for the PTK.
    pub ptk_key_slot: KeySlot<'foa>,
    /// All security associations.
    pub security_associations: SecurityAssociations,
}
impl<'foa> CryptoState<'foa> {
    pub fn new(
        gtk_key_slots: [KeySlot<'foa>; 4],
        ptk_key_slot: KeySlot<'foa>,
        bssid: [u8; 6],
        security_associations: SecurityAssociations,
        message3_replay: crate::rsn_retransmit::Message3Replay,
    ) -> Self {
        let mut temp = Self {
            message3_replay,
            gtk_key_slots,
            last_group_message: None,
            #[cfg(feature = "handshake-probe")]
            group_request_counter: 0,
            ptk_key_slot,
            security_associations,
        };
        temp.program_pairwise_key(bssid);
        temp.program_group_key(temp.security_associations.active_group_id, bssid);
        temp
    }
    /// Commit an authenticated G1. Retries acknowledge the installed key without
    /// resetting hardware or software replay state. Older exchanges do nothing.
    pub fn accept_group_message(&mut self, message: GroupMessage1, bssid: [u8; 6]) -> Option<bool> {
        let counter = self.message3_replay.counter();
        if message.counter < counter {
            return None;
        }
        if message.counter == counter {
            return (self.last_group_message.as_ref() == Some(&message)).then_some(false);
        }
        let id = message.key_id as usize;
        if id >= self.security_associations.group_keys.len() {
            return None;
        }
        // An AP must not move an existing key to a fresh ID and thereby reset its
        // PN protection. Reject this unsupported key reuse without state changes.
        if self
            .security_associations
            .group_keys
            .iter()
            .enumerate()
            .any(|(other, key)| {
                other != id && key.as_ref().is_some_and(|key| key.key == message.key)
            })
        {
            return None;
        }
        let already_installed = self
            .security_associations
            .group_key(message.key_id)
            .is_some_and(|key| key.key == message.key);
        if !already_installed {
            self.security_associations.group_keys[id] = Some(
                TransientKeySecurityAssociation::new(message.key, message.key_id)
                    .with_receive_floor(message.rsc),
            );
            self.program_group_key(message.key_id, bssid);
        }
        self.security_associations.active_group_id = message.key_id;
        self.message3_replay.advance(message.counter);
        self.last_group_message = Some(message);
        Some(!already_installed)
    }
    fn program_group_key(&mut self, id: u8, bssid: [u8; 6]) {
        let key = self.security_associations.group_key(id).unwrap();
        self.gtk_key_slots[id as usize]
            .set_key(
                id,
                bssid,
                CipherParameters::Ccmp(AesCipherParameters {
                    key: MultiLengthKey::Short(&key.key),
                    key_type: KeyType::Group,
                    mfp_enabled: false,
                    spp_enabled: false,
                }),
            )
            .unwrap();
    }
    fn program_pairwise_key(&mut self, bssid: [u8; 6]) {
        self.ptk_key_slot
            .set_key(
                0,
                bssid,
                CipherParameters::Ccmp(AesCipherParameters {
                    key: MultiLengthKey::Short(
                        self.security_associations
                            .pairwise_temporal_key()
                            .try_into()
                            .unwrap(),
                    ),
                    key_type: KeyType::Pairwise,
                    mfp_enabled: false,
                    spp_enabled: false,
                }),
            )
            .unwrap();
    }
}
