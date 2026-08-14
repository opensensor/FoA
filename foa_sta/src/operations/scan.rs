use foa::util::operations::{PostChannelScanAction, ScanConfig};
use futures_util::FutureExt;
use heapless::index_map::FnvIndexMap;

use crate::{StaError, StaTxRx, bss::BSS, rx_router::StaRxRouterEndpoint};

/// Search for a BSS, with the specified [ScanConfig].
///
/// This will return immediately when the first beacon with the specified SSID is received.
pub fn search_for_bss<'foa, 'vif, 'params>(
    sta_tx_rx: &'params StaTxRx<'foa, 'vif>,
    rx_router_endpoint: &'params mut StaRxRouterEndpoint<'foa, 'vif>,
    scan_config: Option<ScanConfig<'params>>,
    ssid: &'params str,
) -> impl Future<Output = Result<BSS, StaError>> + use<'foa, 'vif, 'params> {
    foa::util::operations::scan::<_, BSS>(
        sta_tx_rx.interface_control,
        rx_router_endpoint,
        move |beacon_frame, received_frame, _channel| {
            if beacon_frame.ssid() != Some(ssid) {
                return PostChannelScanAction::Continue;
            }
            let Some(bss) = BSS::from_beacon_like(beacon_frame, received_frame.rssi()) else {
                return PostChannelScanAction::Continue;
            };
            PostChannelScanAction::Stop(bss)
        },
        scan_config,
        false,
    )
    .map(|res| match res {
        Ok(Some(bss)) => Ok(bss),
        Ok(None) => Err(StaError::UnableToFindEss),
        Err(lmac_error) => Err(StaError::LMacError(lmac_error)),
    })
}
/// Enumerate all BSS's, with the specified [ScanConfig].
///
/// The key of the `bss_list` is the BSSID ID, of the network.
/// This will run until either all channels have been scanned, or the `bss_list` is full.
pub fn enumerate_bss<'foa, 'vif, 'params, const MAX_BSS: usize>(
    sta_tx_rx: &'params StaTxRx<'foa, 'vif>,
    rx_router_endpoint: &'params mut StaRxRouterEndpoint<'foa, 'vif>,
    scan_config: Option<ScanConfig<'params>>,
    bss_list: &'params mut FnvIndexMap<[u8; 6], BSS, MAX_BSS>,
) -> impl Future<Output = Result<(), StaError>> {
    foa::util::operations::scan::<_, ()>(
        sta_tx_rx.interface_control,
        rx_router_endpoint,
        |beacon_frame, received_frame, _channel| {
            if bss_list.contains_key(&*beacon_frame.header.bssid) {
                return PostChannelScanAction::Continue;
            }
            if bss_list.len() == bss_list.capacity() {
                trace!(
                    "Can't add BSS with SSID: {:?} and BSSID: {} to scan result list. MAX_BSS: {}",
                    beacon_frame.ssid(),
                    beacon_frame.header.bssid,
                    MAX_BSS
                );
                return PostChannelScanAction::Stop(());
            }
            let Some(bss) = BSS::from_beacon_like(beacon_frame, received_frame.rssi()) else {
                return PostChannelScanAction::Continue;
            };
            let _ = bss_list.insert(*beacon_frame.header.bssid, bss);
            PostChannelScanAction::Continue
        },
        scan_config,
        false,
    )
    .map(|result| result.map(|_| ()).map_err(StaError::LMacError))
}
#[cfg(feature = "alloc")]
/// Scan continuously for networks and run the call back whenever one is found.
///
/// When the callback returns false the scan will be stopped and the future finishes.
pub fn scan_continuously<'foa, 'vif, 'params>(
    sta_tx_rx: &'params StaTxRx<'foa, 'vif>,
    rx_router_endpoint: &'params mut StaRxRouterEndpoint<'foa, 'vif>,
    scan_config: Option<ScanConfig<'params>>,
    bss_list: &'params mut alloc::collections::BTreeMap<[u8; 6], BSS>,
    bss_found_cb: fn(&BSS) -> bool,
) -> impl Future<Output = Result<(), StaError>> {
    foa::util::operations::scan::<_, ()>(
        sta_tx_rx.interface_control,
        rx_router_endpoint,
        move |beacon_frame, received_frame, _channel| {
            if bss_list.contains_key(&*beacon_frame.header.bssid) {
                return PostChannelScanAction::Continue;
            }
            let Some(bss) = BSS::from_beacon_like(beacon_frame, received_frame.rssi()) else {
                return PostChannelScanAction::Continue;
            };
            let action = if bss_found_cb(&bss) {
                PostChannelScanAction::Continue
            } else {
                PostChannelScanAction::Stop(())
            };
            let _ = bss_list.insert(*beacon_frame.header.bssid, bss);
            action
        },
        scan_config,
        true,
    )
    .map(|result| result.map(|_| ()).map_err(StaError::LMacError))
}
