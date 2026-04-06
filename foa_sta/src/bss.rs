use ieee80211::{
    elements::{
        DSSSParameterSetElement,
        rsn::{IEEE80211AkmType, IEEE80211CipherSuiteSelector, OptionalFeatureConfig, RsnElement},
    },
    mac_parser::MACAddress,
    mgmt_frame::{ManagementFrame, body::BeaconLikeBody},
};

#[derive(Default)]
struct RsnReport {
    group_cipher: IEEE80211CipherSuiteSelector,

    ccmp_present: bool,
    gcmp_present: bool,
    tkip_present: bool,

    owe_present: bool,
    sae_present: bool,
    psk_present: bool,

    mfp_required: bool,
}
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Configuration of a WPA2 network.
pub struct Wpa2Config {
    /// Is management frame protection required.
    pub mfp_required: bool,
}
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The security configuration of a BSS.
///
/// This is derived from the RSN Element or lack thereof, and represents the equivalent security
/// specification.
pub enum SecurityConfig {
    /// Unsecured
    Open,
    /// Wired Equivalent Privacy
    ///
    /// WARNING: Broken beyond repair.
    Wep,
    /// Wi-Fi Protected Access
    ///
    /// WARNING: Broken beyond repair.
    Wpa,
    /// Wi-Fi Protected Access 2 Transition Mode
    ///
    /// WARNING: In terms of group addressed traffic, this is just as broken as WPA.
    Wpa2TransitionMode,
    /// Wi-Fi Protected Access 2
    ///
    /// WPA2 to this day holds all it's security guarantess, which however do **NOT** include
    /// forward or backward secrecy. This means that if an attacker knows the passphrase, they can
    /// passively decrypt all traffic, just by sniffing the 4WHS. WPA3 fixes these issues.
    ///
    /// Frostie314159: This always causes me massive facepalms, when there's a public Wi-Fi
    /// network, that's supposedly secure, because it uses WPA2-PSK, but the key is plastered
    /// everywhere. This "attack" is in fact so simple, that it's a builtin feature in wireshark.
    Wpa2(Wpa2Config),
    /// Wi-Fi Protected Access 3 Transition Mode
    ///
    /// This allows WPA2 and WPA3 capable devices to connect, but comes with the drawback, that if
    /// an attack knows the key and was able to capture a 4WHS of a WPA2 device, they can still
    /// decrypt and forge group addressed frames of WPA2 and WPA3 devices, as well as pairwise
    /// frames of WPA2 devices.
    Wpa3TransitionMode,
    /// Wi-Fi Protected Access 3
    ///
    /// This is the most secure configuration, since there are currently no attacks, that would
    /// allow any kind of forgery or decryption, by an attack with knowledge of the key.
    Wpa3,
    /// Opportunistic Wireless Encryption Transition Mode
    ///
    /// This is the middle ground between an open and an OWE network. Group addressed frames are
    /// still vulnerable.
    OweTransitionMode,
    /// Opportunistic Wireless Encryption
    ///
    /// This is like an open network, but the traffic is still encrypted. It does not provide any
    /// authentication. Using this instead of WPA2 for a public network is the sensible approach,
    /// if absolutely no access control is required.
    Owe,
    /// No equivalent was found, or the configuration is invalid.
    Invalid,
}
impl SecurityConfig {
    fn generate_rsn_report(rsn: &RsnElement<'_>) -> Option<RsnReport> {
        let mut rsn_report = RsnReport::default();

        rsn_report.group_cipher = rsn.group_data_cipher_suite?;
        if let Some(rsn_capabilities) = rsn.rsn_capbilities {
            if rsn_capabilities.mfp_config() == OptionalFeatureConfig::Invalid {
                return None;
            }
            rsn_report.mfp_required = rsn_capabilities.mfp_config().is_required();
        }
        rsn.pairwise_cipher_suite_list?
            .for_each(|cipher_suite| match cipher_suite {
                IEEE80211CipherSuiteSelector::Ccmp128 | IEEE80211CipherSuiteSelector::Ccmp256 => {
                    rsn_report.ccmp_present = true
                }
                IEEE80211CipherSuiteSelector::Gcmp128 | IEEE80211CipherSuiteSelector::Gcmp256 => {
                    rsn_report.gcmp_present = true
                }
                IEEE80211CipherSuiteSelector::Tkip => rsn_report.tkip_present = true,
                _ => {}
            });

        rsn.akm_list?.for_each(|akm_suite| match akm_suite {
            IEEE80211AkmType::OpportunisticWirelessEncryption => rsn_report.owe_present = true,
            IEEE80211AkmType::Psk => rsn_report.psk_present = true,
            IEEE80211AkmType::Sae => rsn_report.sae_present = true,
            _ => {}
        });

        Some(rsn_report)
    }
    pub(crate) fn from_beacon_like<Subtype>(
        frame: &ManagementFrame<BeaconLikeBody<'_, Subtype>>,
    ) -> Self {
        let Some(rsn) = frame.elements.get_first_element::<RsnElement>() else {
            return Self::Open;
        };
        let Some(rsn_report) = Self::generate_rsn_report(&rsn) else {
            return Self::Invalid;
        };

        let is_group_cipher_ccmp = rsn_report.group_cipher == IEEE80211CipherSuiteSelector::Ccmp128;
        let is_group_cipher_tkip = rsn_report.group_cipher == IEEE80211CipherSuiteSelector::Tkip;
        if is_group_cipher_ccmp && rsn_report.ccmp_present {
            if rsn_report.owe_present {
                Self::Owe
            } else {
                match (rsn_report.psk_present, rsn_report.sae_present) {
                    (true, true) => Self::Wpa3TransitionMode,
                    (true, false) => Self::Wpa2(Wpa2Config {
                        mfp_required: rsn_report.mfp_required,
                    }),
                    (false, true) => Self::Wpa3,
                    _ => Self::Invalid,
                }
            }
        } else if is_group_cipher_tkip && rsn_report.tkip_present {
            if rsn_report.ccmp_present {
                Self::Wpa2TransitionMode
            } else {
                Self::Wpa
            }
        } else {
            Self::Invalid
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
/// Information about a BSS.
pub struct BSS {
    /// The SSID of the BSS.
    pub ssid: heapless::String<32>,
    /// The channel on which the BSS operates.
    ///
    /// NOTE: This is taken from the DSSS Parameter Set Element and not just the channel on which
    /// we received the beacon.
    pub channel: u8,
    /// The BSSID of the BSS.
    pub bssid: MACAddress,
    /// The RSSI in dBm of the last frame received from this BSS.
    pub last_rssi: i8,
    /// The security configuration of the network.
    pub security_config: SecurityConfig,
}
impl BSS {
    /// Create a [BSS] from the information in a beacon or probe response frame.
    pub fn from_beacon_like<Subtype>(
        frame: ManagementFrame<BeaconLikeBody<'_, Subtype>>,
        rssi: i8,
    ) -> Option<Self> {
        let mut ssid = heapless::String::new();
        let _ = ssid.push_str(frame.ssid()?);
        let channel = frame
            .elements
            .get_first_element::<DSSSParameterSetElement>()?
            .current_channel;
        let bssid = frame.header.bssid;
        let security_config = SecurityConfig::from_beacon_like(&frame);
        Some(Self {
            ssid,
            channel,
            bssid,
            last_rssi: rssi,
            security_config,
        })
    }
}
#[cfg(feature = "rsn")]
pub(crate) struct PskLengthMismatchError;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Network credentials.
pub enum Credentials<'a> {
    /// A pre shared key (PSK).
    PreSharedKey(&'a [u8]),
    /// A passphrase.
    ///
    /// We internally convert this to a PSK for further processing.
    Passphrase(&'a str),
}
impl Credentials<'_> {
    #[cfg(feature = "rsn")]
    /// Get the PMK for the provided credentials.
    ///
    /// If this is a PSK and the length doesn't match the provided output slice,
    /// [PskLengthMismatchError] is returned.
    pub(crate) fn pmk(&self, output: &mut [u8], ssid: &str) -> Result<(), PskLengthMismatchError> {
        match self {
            Self::PreSharedKey(psk) => {
                if output.len() == psk.len() {
                    output.copy_from_slice(psk);
                } else {
                    return Err(PskLengthMismatchError);
                }
            }
            Self::Passphrase(passphrase) => {
                ieee80211::crypto::map_passphrase_to_psk(passphrase, ssid, output)
            }
        }
        Ok(())
    }
}
