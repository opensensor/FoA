//! This module provides control over the STA interface.

use heapless::index_map::FnvIndexMap;
use ieee80211::{common::AssociationID, mac_parser::MACAddress};

use foa::{
    esp_wifi_hal::prelude::*,
    util::{
        operations::{ScanConfig, deauthenticate},
        random_mac_address,
    },
};

use crate::{
    ConnectionConfig, SecurityConfig, StaTxRx,
    bss::{BSS, Credentials},
    connection_state::{ConnectionInfo, ConnectionState, DisconnectionReason},
    operations::{
        connect::{self, ConnectionParameters},
        scan::{self},
    },
    rx_router::StaRxRouterEndpoint,
};

use super::StaError;

/// This provides control over the STA interface.
pub struct StaControl<'foa, 'vif> {
    // Low level RX/TX.
    pub(crate) rx_router_endpoint: StaRxRouterEndpoint<'foa, 'vif>,
    pub(crate) sta_tx_rx: &'vif StaTxRx<'foa, 'vif>,

    // Misc.
    pub(crate) mac_address: MACAddress,
}
impl<'foa, 'vif> StaControl<'foa, 'vif> {
    /// Diagnostic: ask the current AP to rotate its group key using an
    /// authenticated EAPOL-Key Request. This can rotate the key for every STA
    /// in the BSS; it is opt-in and never called by normal connection handling.
    /// Success means the MAC reported successful transmission, not that the AP
    /// rotated its key. A missing completion returns [`StaError::TxCompletionLost`];
    /// the radio outcome is unknown and the request is not automatically resubmitted.
    #[cfg(all(feature = "rsn", feature = "handshake-probe"))]
    pub async fn request_group_rekey(&mut self) -> Result<(), StaError> {
        let info = self
            .sta_tx_rx
            .connection_state
            .connection_info()
            .ok_or(StaError::NotConnected)?;
        let (kck, counter) = self
            .sta_tx_rx
            .map_crypto_state(|state| {
                let sa = &state.security_associations;
                let (kck, _, _) =
                    ieee80211::crypto::partition_ptk(&sa.ptksa.key, sa.akm_suite, sa.cipher_suite)?;
                let kck: [u8; 16] = kck.try_into().ok()?;
                let counter = state.group_request_counter;
                state.group_request_counter = counter.checked_add(1)?;
                Some((kck, counter))
            })
            .flatten()
            .ok_or(StaError::GroupKeyHandshakeFailure)?;
        connect::send_group_request(
            self.sta_tx_rx,
            info.bss.bssid,
            info.own_address,
            &kck,
            counter,
        )
        .await
    }
    /// Set the MAC address for the STA interface.
    pub fn set_mac_address(&mut self, mac_address: [u8; 6]) -> Result<(), StaError> {
        if self.sta_tx_rx.connection_state.connection_info().is_some() {
            Err(StaError::StillConnected)
        } else {
            self.mac_address = MACAddress::new(mac_address);
            Ok(())
        }
    }
    /// Randomize the MAC address.
    ///
    /// This will also return the MAC address.
    pub fn randomize_mac_address(&mut self) -> Result<[u8; 6], StaError> {
        let mac_address = random_mac_address();
        self.set_mac_address(mac_address).map(|_| mac_address)
    }

    /// Scan for networks.
    ///
    /// Invalid channels will cause an error to be returned.
    pub fn scan<'params, const MAX_ESS: usize>(
        &'params mut self,
        scan_config: Option<ScanConfig<'params>>,
        found_bss: &'params mut FnvIndexMap<[u8; 6], BSS, MAX_ESS>,
    ) -> impl Future<Output = Result<(), StaError>> {
        scan::enumerate_bss(
            self.sta_tx_rx,
            &mut self.rx_router_endpoint,
            scan_config,
            found_bss,
        )
    }
    #[cfg(feature = "alloc")]
    /// Scan continuously for networks and run the call back whenever one is found.
    ///
    /// When the callback returns false the scan will be stopped and the future finishes.
    pub fn scan_continuously<'params>(
        &'params mut self,
        scan_config: Option<ScanConfig<'params>>,
        found_bss: &'params mut alloc::collections::BTreeMap<[u8; 6], BSS>,
        bss_found_cb: fn(&BSS) -> bool,
    ) -> impl Future<Output = Result<(), StaError>> + use<'foa, 'vif, 'params> {
        scan::scan_continuously(
            self.sta_tx_rx,
            &mut self.rx_router_endpoint,
            scan_config,
            found_bss,
            bss_found_cb,
        )
    }
    /// Look for a specific ESS and break once the first match is found.
    pub fn find_ess<'params>(
        &'params mut self,
        scan_config: Option<ScanConfig<'params>>,
        ssid: &'params str,
    ) -> impl Future<Output = Result<BSS, StaError>> + use<'foa, 'vif, 'params> {
        scan::search_for_bss(
            self.sta_tx_rx,
            &mut self.rx_router_endpoint,
            scan_config,
            ssid,
        )
    }
    /// Connect to a network.
    ///
    /// If we're already connected to a network, this will disconnect from that network, before
    /// establishing a connection to the new network.
    pub async fn connect(
        &mut self,
        bss: BSS,
        connection_config: Option<ConnectionConfig>,
        credentials: Option<Credentials<'_>>,
    ) -> Result<(), StaError> {
        if bss.security_config != SecurityConfig::Open && credentials.is_none() {
            return Err(StaError::NoCredentialsForNetwork);
        }
        if let Some(connection_info) = self.sta_tx_rx.connection_state.connection_info() {
            if connection_info.bss.bssid == bss.bssid {
                return Err(StaError::SameNetwork);
            }
            debug!("Disconnecting from {}.", connection_info.bss.bssid);
            self.disconnect_internal(&connection_info).await;
        }
        self.sta_tx_rx.reset_phy_rate();
        let connection_config = connection_config.unwrap_or_default();
        let aid = connect::connect(
            self.sta_tx_rx,
            &mut self.rx_router_endpoint,
            &bss,
            &ConnectionParameters {
                config: connection_config,
                own_address: self.mac_address,
                credentials,
            },
        )
        .await?;
        debug!(
            "Successfully connected to {} : \"{}\"",
            bss.bssid,
            bss.ssid.as_str()
        );
        self.sta_tx_rx
            .connection_state
            .signal_state(ConnectionState::Connected(ConnectionInfo {
                bss,
                own_address: self.mac_address,
                aid,
                connection_config,
            }));
        Ok(())
    }
    /// Connect to a network based on it's SSID.
    ///
    /// This will search for the network and connect to the first one it finds.
    pub async fn connect_by_ssid(
        &mut self,
        ssid: &str,
        connection_config: Option<ConnectionConfig>,
        credentials: Option<Credentials<'_>>,
    ) -> Result<(), StaError> {
        let bss = self.find_ess(None, ssid).await?;
        self.connect(bss, connection_config, credentials).await
    }
    fn disconnect_internal(
        &mut self,
        ConnectionInfo {
            bss, own_address, ..
        }: &ConnectionInfo,
    ) -> impl Future {
        // NOTE: The channel is already unlocked here, but since there's no await-point between
        // unlocking the channel and transmitting the deauth, no other interface could attempt to
        // lock it before we're done here.
        self.sta_tx_rx
            .connection_state
            .signal_state(ConnectionState::Disconnected(DisconnectionReason::User));
        self.sta_tx_rx.reset_phy_rate();
        deauthenticate(
            self.sta_tx_rx.tx_endpoint,
            bss.bssid,
            *own_address,
            true,
            self.sta_tx_rx.phy_rate(),
        )
    }
    /// Disconnect from the current network.
    pub async fn disconnect(&mut self) -> Result<(), StaError> {
        let Some(connection_info) = self.sta_tx_rx.connection_state.connection_info() else {
            return Err(StaError::NotConnected);
        };
        self.sta_tx_rx.interface_control.unlock_channel();
        self.disconnect_internal(&connection_info).await;
        debug!("Disconnected from {}", connection_info.bss.bssid);
        Ok(())
    }
    /// Check if we're currently connected to a network.
    pub fn connected(&self) -> bool {
        self.sta_tx_rx.connection_state.connected()
    }
    /// Get the [AssociationID] of the current connection.
    pub fn get_aid(&self) -> Option<AssociationID> {
        self.sta_tx_rx
            .connection_state
            .map_connection_info(|connection_info| connection_info.aid)
    }
    /// Get the currently used PHY rate.
    pub fn phy_rate(&self) -> TxPhyRate {
        self.sta_tx_rx.phy_rate()
    }
    /// Override the PHY rate.
    pub fn override_phy_rate(&self, phy_rate: TxPhyRate) {
        self.sta_tx_rx.set_phy_rate(phy_rate);
    }
}
