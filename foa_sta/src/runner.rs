use core::{future::pending, marker::PhantomData};

use embassy_futures::{
    join::join,
    select::{Either3, select3},
};
use embassy_net_driver::{HardwareAddress, LinkState};
use embassy_net_driver_channel::{RxRunner, StateRunner, TxRunner};
use embassy_time::Ticker;
use ethernet::{Ethernet2Frame, Ethernet2Header};
use foa::{
    ReceivedFrame, RetryBehaviour, RxEndpoint,
    esp_wifi_hal::{ll::EdcaAccessCategory, prelude::*},
    util::{operations::deauthenticate, rx_router::RxRouterQueue},
};
use futures_util::FutureExt;
use ieee80211::{
    GenericFrame,
    common::{DataFrameSubtype, FCFFlags, FrameType, SequenceControl},
    crypto::{CryptoHeader, MicState},
    data_frame::{
        DataFrame, DataFrameReadPayload, PotentiallyWrappedPayload, header::DataFrameHeader,
    },
    mac_parser::MACAddress,
    match_frames,
    mgmt_frame::{BeaconFrame, DeauthenticationFrame},
    scroll::{Pread, Pwrite},
};
use llc_rs::SnapLlcFrame;

use crate::{
    MTU, StaTxRx,
    connection_state::{ConnectionInfo, ConnectionState, DisconnectionReason},
    rx_router::{StaRxRouterEndpoint, StaRxRouterInput, StaRxRouterOperation},
};
enum ConnectionRxEvent {
    Disconnected(DisconnectionReason),
    BeaconReceived,
}

pub(crate) struct ConnectionRunner<'foa, 'vif> {
    // Low level RX/TX.
    pub(crate) rx_router_endpoint: StaRxRouterEndpoint<'foa, 'vif>,
    pub(crate) sta_tx_rx: &'vif StaTxRx<'foa, 'vif>,

    // Upper layer control.
    pub(crate) state_runner: StateRunner<'vif>,
}
impl ConnectionRunner<'_, '_> {
    #[cfg(feature = "rsn")]
    async fn handle_eapol_retry(&self, mut buffer: ReceivedFrame<'_>, info: &ConnectionInfo) {
        let mut scratch = self.sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let reply = self
            .sta_tx_rx
            .map_crypto_state(|state| {
                let sa = &state.security_associations;
                let (kck, kek, _) =
                    ieee80211::crypto::partition_ptk(&sa.ptksa.key, sa.akm_suite, sa.cipher_suite)?;
                let kck: &[u8; 16] = kck.try_into().ok()?;
                let kek: &[u8; 16] = kek.try_into().ok()?;
                let counter = state.message3_replay.accept(
                    buffer.mpdu_buffer_mut(),
                    scratch.as_mut_slice(),
                    kck,
                    kek,
                    &sa.gtksa.key,
                    sa.gtksa.key_id,
                    info.own_address,
                    info.bss.bssid,
                )?;
                Some((*kck, state.message3_replay.supplicant_nonce, counter))
            })
            .flatten();
        drop(scratch);
        drop(buffer);
        #[cfg(feature = "handshake-probe")]
        crate::handshake_probe::event(12, reply.is_some() as u32, 0);
        if let Some((kck, nonce, counter)) = reply {
            let _result = crate::operations::connect::send_message_4(
                self.sta_tx_rx,
                info.bss.bssid,
                info.own_address,
                &kck,
                &nonce,
                counter,
            )
            .await;
            #[cfg(feature = "handshake-probe")]
            crate::handshake_probe::event(13, _result.is_err() as u32, 0);
        }
    }
    /// Handle a deauth frame.
    ///
    /// NOTE: Currently this immediately leads to disconnection.
    fn handle_deauth(
        &self,
        deauth: DeauthenticationFrame<'_>,
        _rx_timestamp: u32,
    ) -> ConnectionRxEvent {
        #[cfg(feature = "connection-trace")]
        {
            let matches = self.sta_tx_rx.connection_state.map_connection_info(|info| {
                (
                    deauth.header.transmitter_address == info.bss.bssid,
                    deauth.header.bssid == info.bss.bssid,
                    deauth.header.receiver_address == info.own_address,
                )
            });
            let (transmitter_matches, bssid_matches, receiver_matches) =
                matches.unwrap_or((false, false, false));
            log::info!(
                "stage=sta_deauth us={} rx_timestamp={} reason={} connected={} transmitter_matches={} bssid_matches={} receiver_matches={} group={} sequence={} retry={} protected={}",
                embassy_time::Instant::now().as_micros(),
                _rx_timestamp,
                deauth.reason.into_bits(),
                matches.is_some(),
                transmitter_matches,
                bssid_matches,
                receiver_matches,
                deauth.header.receiver_address.is_multicast(),
                deauth.header.sequence_control.sequence_number(),
                deauth.header.fcf_flags.retry(),
                deauth.header.fcf_flags.protected(),
            );
        }
        debug!(
            "Received deauthentication frame from {}, reason: {:?}.",
            deauth.header.transmitter_address, deauth.reason
        );
        ConnectionRxEvent::Disconnected(DisconnectionReason::Deauthenticated)
    }
    /// Handle a frame arriving on the background queue, during a connection.
    fn handle_bg_rx(&self, buffer: ReceivedFrame<'_>) -> Option<ConnectionRxEvent> {
        match_frames! {
            buffer.mpdu_buffer(),
            deauth = DeauthenticationFrame => {
                self.handle_deauth(deauth, buffer.timestamp())
            }
            _beacon = BeaconFrame => {
                ConnectionRxEvent::BeaconReceived
            }
        }
        .ok()
    }
    /// Run the background task.
    ///
    /// This will return if we are deauthenticated or a beacon timeout occurs.
    async fn run_connection(
        &self,
        info @ ConnectionInfo {
            bss,
            own_address,
            connection_config,
            ..
        }: &ConnectionInfo,
    ) -> DisconnectionReason {
        let mut beacon_timeout = connection_config.beacon_timeout.map(Ticker::every);
        loop {
            // We wait for one of three things to happen.
            // 1. An off channel request arrives, which we grant immediately and wait for its
            //    completion.
            // 2. A frame to arrive from the background queue.
            // 3. A beacon timeout to occur.
            match select3(
                self.sta_tx_rx
                    .interface_control
                    .wait_for_off_channel_request(),
                self.rx_router_endpoint.receive(),
                async {
                    if let Some(ref mut ticker) = beacon_timeout {
                        ticker.next().await
                    } else {
                        pending().await
                    }
                },
            )
            .await
            {
                Either3::First(off_channel_request) => {
                    off_channel_request.grant();
                    self.sta_tx_rx
                        .interface_control
                        .wait_for_off_channel_completion()
                        .await;
                }
                Either3::Second(buffer) => {
                    #[cfg(feature = "rsn")]
                    if GenericFrame::new(buffer.mpdu_buffer(), false)
                        .is_ok_and(|frame| frame.is_eapol_key_frame())
                    {
                        self.handle_eapol_retry(buffer, info).await;
                        continue;
                    }
                    if let Some(connection_rx_event) = self.handle_bg_rx(buffer) {
                        match connection_rx_event {
                            ConnectionRxEvent::Disconnected(disconnection_reason) => {
                                return disconnection_reason;
                            }
                            ConnectionRxEvent::BeaconReceived => {
                                beacon_timeout.as_mut().map(Ticker::reset);
                            }
                        }
                    }
                }
                Either3::Third(_) => {
                    // Since we assume the network can either not or barely hear us, we use the
                    // lowest PHY rate.
                    deauthenticate(
                        self.sta_tx_rx.tx_endpoint,
                        bss.bssid,
                        *own_address,
                        true,
                        OfdmRate::Mbits6.into(),
                    )
                    .await;
                    debug!("Disconnected from BSS due to beacon timeout.");
                    return DisconnectionReason::BeaconTimeout;
                }
            }
        }
    }
    /// Handle the tranmsission of MSDUs.
    async fn run_msdu_tx(
        tx_runner: &mut TxRunner<'_, MTU>,
        sta_tx_rx: &StaTxRx<'_, '_>,
        connection_info: &ConnectionInfo,
    ) -> ! {
        loop {
            let msdu = tx_runner.tx_buf().await;

            // We don't want to accidentally transmit a MSDU, while we're not on channel.
            if sta_tx_rx.in_off_channel_operation() {
                sta_tx_rx
                    .interface_control
                    .wait_for_off_channel_completion()
                    .await;
            }
            let Ok(ethernet_frame) = msdu.pread::<Ethernet2Frame>(0) else {
                continue;
            };
            let mut tx_buf = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
            let data_frame = DataFrame {
                header: DataFrameHeader {
                    subtype: DataFrameSubtype::Data,
                    fcf_flags: FCFFlags::new().with_to_ds(true),
                    address_1: connection_info.bss.bssid,
                    address_2: connection_info.own_address,
                    address_3: ethernet_frame.header.dst,
                    sequence_control: SequenceControl::new(),
                    ..Default::default()
                },
                payload: Some(SnapLlcFrame {
                    oui: [0x00; 3],
                    ether_type: ethernet_frame.header.ether_type,
                    payload: ethernet_frame.payload,
                    _phantom: PhantomData,
                }),
                _phantom: PhantomData,
            };

            cfg_select! {
                feature = "rsn" => {
                    let tx_crypto_info = sta_tx_rx.map_crypto_state(|crypto_state| {
                        (
                            crypto_state
                                .security_associations
                                .ptksa
                                .next_packet_number(),
                            crypto_state.security_associations.ptksa.key_id,
                            crypto_state.ptk_key_slot.key_slot(),
                        )
                    });
                },
                _ => {
                    let tx_crypto_info = None::<(u64, u8, usize)>;
                }

            }
            let Some((written, key_slot)) =
                (if let Some((new_packet_number, key_id, key_slot)) = tx_crypto_info {
                    tx_buf
                        .pwrite(
                            data_frame.crypto_wrap(
                                CryptoHeader::new(new_packet_number, key_id).unwrap(),
                                MicState::Short,
                            ),
                            0,
                        )
                        .ok()
                        .map(|written| (written, Some(key_slot as u8)))
                } else {
                    tx_buf.pwrite(data_frame, 0).ok().zip(Some(None))
                })
            else {
                continue;
            };
            let _ = sta_tx_rx.tx_endpoint.transmit_edca(
                EdcaAccessCategory::default(),
                tx_buf,
                written,
                TxPlcpParameters {
                    rate: sta_tx_rx.phy_rate(),
                    ..Default::default()
                },
                TxMacParameters {
                    key_slot_index: key_slot,
                    wait_for_ack: true,
                    // Each newly generated MSDU needs a fresh MPDU sequence;
                    // the driver keeps it unchanged across its MAC retries.
                    override_seq_num: true,
                    ..Default::default()
                },
                RetryBehaviour::RetryUntil(7),
            );
            trace!(
                "Transmitted {} bytes to {}",
                msdu.len(),
                ethernet_frame.header.dst
            );
            tx_runner.tx_done();
        }
    }
    /// Run all actual background operations.
    async fn run(&mut self, tx_runner: &mut TxRunner<'_, MTU>) -> ! {
        loop {
            let connection_info = self.sta_tx_rx.connection_state.wait_for_connection().await;
            self.state_runner
                .set_hardware_address(HardwareAddress::Ethernet(*connection_info.own_address));
            self.state_runner.set_link_state(LinkState::Up);
            #[cfg(feature = "connection-trace")]
            log::info!(
                "stage=sta_link us={} up=true beacon_timeout_ms={} automatic_reconnect={}",
                embassy_time::Instant::now().as_micros(),
                connection_info
                    .connection_config
                    .beacon_timeout
                    .map(|d| d.as_millis())
                    .unwrap_or(0),
                connection_info.connection_config.automatic_reconnect,
            );
            debug!("Link went up.");
            // At this point, the channel will have been locked, so we'll only receive off channel
            // requests, while we're connected.

            // Run the connection, until we're disconnected.
            let disconnection_reason = match select3(
                self.sta_tx_rx.connection_state.wait_for_disconnection(),
                self.run_connection(&connection_info),
                Self::run_msdu_tx(tx_runner, self.sta_tx_rx, &connection_info),
            )
            .await
            {
                Either3::First(disconnection_reason) | Either3::Second(disconnection_reason) => {
                    disconnection_reason
                }
                Either3::Third(_) => unreachable!(),
            };
            #[cfg(feature = "connection-trace")]
            log::info!(
                "stage=sta_link us={} up=false reason={} off_channel={}",
                embassy_time::Instant::now().as_micros(),
                match disconnection_reason {
                    DisconnectionReason::User => "user",
                    DisconnectionReason::BeaconTimeout => "beacon_timeout",
                    DisconnectionReason::Deauthenticated => "deauthenticated",
                },
                self.sta_tx_rx.in_off_channel_operation(),
            );
            if tx_runner.try_tx_buf().is_some() {
                tx_runner.tx_done();
            }
            // We reset all connection specific parameters here.
            // Unlocking the channel was already done, by any path leading to disconnection.
            self.sta_tx_rx.interface_control.unlock_channel();
            self.sta_tx_rx.reset_phy_rate();
            self.sta_tx_rx
                .interface_control
                .clear_filter(RxFilterBank::Bssid);
            self.sta_tx_rx
                .connection_state
                .signal_state(ConnectionState::Disconnected(disconnection_reason));
            self.state_runner.set_link_state(LinkState::Down);
            debug!("Link went down.");
        }
    }
}
pub(crate) struct RoutingRunner<'foa, 'vif> {
    // Low level RX/TX.
    pub(crate) rx_router_input: StaRxRouterInput<'foa, 'vif>,
    pub(crate) interface_rx_endpoint: RxEndpoint<'foa, 'vif>,
    pub(crate) sta_tx_rx: &'vif StaTxRx<'foa, 'vif>,

    // Upper layer control.
    pub(crate) rx_runner: RxRunner<'vif, MTU>,
}
impl RoutingRunner<'_, '_> {
    #[allow(unused)]
    fn process_potentially_wrapped_payload<'a>(
        &self,
        is_group: bool,
        payload: PotentiallyWrappedPayload<DataFrameReadPayload<'a>>,
    ) -> Option<DataFrameReadPayload<'a>> {
        match payload {
            PotentiallyWrappedPayload::Unwrapped(payload) => Some(payload),
            PotentiallyWrappedPayload::CryptoWrapped(crypto_wrapper) => {
                #[cfg(feature = "rsn")]
                return self
                    .sta_tx_rx
                    .map_crypto_state(|crypto_state| {
                        let security_associations = &crypto_state.security_associations;
                        let packet_number = crypto_wrapper.crypto_header.packet_number();
                        let packet_number_valid = if is_group {
                            security_associations
                                .gtksa
                                .update_and_validate_replay_counter(packet_number)
                        } else {
                            security_associations
                                .ptksa
                                .update_and_validate_replay_counter(packet_number)
                        };
                        packet_number_valid.then_some(crypto_wrapper.payload)
                    })
                    .flatten();
                #[cfg(not(feature = "rsn"))]
                return None;
            }
        }
    }
    /// Handover a single MSDU to embassy_net.
    fn handle_downlink_msdu(
        &mut self,
        payload: &[u8],
        source_address: MACAddress,
        destination_address: MACAddress,
    ) -> Option<()> {
        // The body of every data frame contains a logical link control (LLC) frame, as specified
        // in IEEE 802.2.
        let llc_payload = payload.pread::<SnapLlcFrame>(0).ok()?;
        // We don't wait on an RX buffer becoming available here, since doing so could stall the
        // routing task.
        let Some(rx_buf) = self.rx_runner.try_rx_buf() else {
            trace!("Dropping MSDU, because no buffers are available.");
            return None;
        };
        // Here we serialize the ethernet frame.
        let Ok(written) = rx_buf.pwrite(
            Ethernet2Frame {
                header: Ethernet2Header {
                    dst: destination_address,
                    src: source_address,
                    ether_type: llc_payload.ether_type,
                },
                payload: llc_payload.payload,
            },
            0,
        ) else {
            return None;
        };
        self.rx_runner.rx_done(written);
        Some(())
    }
    /// Forward a received data frame to higher layers.
    fn handle_data_rx(&mut self, data_frame: DataFrame<'_, &[u8]>) -> Option<()> {
        let destination_address = data_frame.header.destination_address()?;
        let source_address = data_frame.header.source_address()?;
        let Some(payload) = self.process_potentially_wrapped_payload(
            destination_address.is_multicast(),
            data_frame.potentially_wrapped_payload(Some(MicState::NotPresent))?,
        ) else {
            info!("Dropping MSDU.");
            return None;
        };
        match payload {
            DataFrameReadPayload::Single(payload) => {
                self.handle_downlink_msdu(payload, *source_address, *destination_address)
            }
            DataFrameReadPayload::AMSDU(mut amsdu_sub_frame_iterator) => amsdu_sub_frame_iterator
                .try_for_each(|sub_frame| {
                    self.handle_downlink_msdu(
                        sub_frame.payload,
                        sub_frame.source_address,
                        sub_frame.destination_address,
                    )
                }),
        }
    }
    fn connecting_mac_address(&self) -> Option<MACAddress> {
        self.rx_router_input
            .operation(RxRouterQueue::Foreground)
            .or_else(|| self.rx_router_input.operation(RxRouterQueue::Background))
            .and_then(StaRxRouterOperation::connecting_mac_address)
    }
    /// Run the routing task.
    async fn run(&mut self) -> ! {
        loop {
            let borrowed_buffer = self.interface_rx_endpoint.receive().await;
            // We create a generic frame, to do matching.
            let Ok(generic_frame) = GenericFrame::new(borrowed_buffer.mpdu_buffer(), false) else {
                continue;
            };
            trace!(
                "RX type: {:?}",
                generic_frame.frame_control_field().frame_type()
            );
            let address_1 = generic_frame.address_1();
            // Here we toss out frames, where the first address doesn't meet one of these conditions:
            // 1. Is multicast
            // 2. Is the address, with which we're already associated with a BSS.
            // 3. Is the address, with which we're currently associating with a BSS.
            if !address_1.is_multicast()
                && let Some(own_address) = self
                    .sta_tx_rx
                    .connection_state
                    .connection_info()
                    .map(|connection_info| connection_info.own_address)
                    .or_else(|| self.connecting_mac_address())
                && own_address != address_1
            {
                continue;
            }

            // We won't process any frames, while another interface is doing an off channel
            // operation.
            if !self.sta_tx_rx.in_off_channel_operation()
                && self
                    .sta_tx_rx
                    .interface_control
                    .off_channel_operation_in_progress()
            {
                continue;
            }
            // To reduce latency, we process all data frames here directly, if we are connected.
            if self.sta_tx_rx.connection_state.connected() {
                if generic_frame.is_eapol_key_frame() {
                    // This distinction is here, since GTK rekeys will happen, and those frames
                    // should go to the background task.
                    if !self.sta_tx_rx.rsna_activated() {
                        debug!("Discarding EAPOL Key Frame, since RSNA isn't activated.");
                    }
                } else if let FrameType::Data(_) = generic_frame.frame_control_field().frame_type()
                {
                    let Some(Ok(data_frame)) = generic_frame.parse_to_typed() else {
                        continue;
                    };
                    // We don't want to process data frames during an off channel operation, since
                    // otherwise it would be possible to inject frames on other channels.
                    if self.sta_tx_rx.in_off_channel_operation() {
                        continue;
                    }
                    self.handle_data_rx(data_frame);
                    continue;
                }
            }
            // We ask the RX router, where all other frames should go.
            #[cfg(feature = "connection-trace")]
            let management_trace = match_frames! {
                borrowed_buffer.mpdu_buffer(),
                frame = DeauthenticationFrame => { (12u8, frame.header, frame.reason.into_bits()) }
                frame = ieee80211::mgmt_frame::DisassociationFrame => { (10u8, frame.header, frame.reason.into_bits()) }
            }.ok().map(|(subtype, header, reason)| {
                let matches = self.sta_tx_rx.connection_state.map_connection_info(|info| (
                    header.transmitter_address == info.bss.bssid,
                    header.bssid == info.bss.bssid,
                    header.receiver_address == info.own_address,
                ));
                let (ta, bssid, ra) = matches.unwrap_or((false, false, false));
                log::info!(
                    "stage=sta_mgmt_rx us={} rx_timestamp={} subtype={} reason={} connected={} transmitter_matches={} bssid_matches={} receiver_matches={} group={} sequence={} fragment={} retry={} protected={} foreground_operation={}",
                    embassy_time::Instant::now().as_micros(), borrowed_buffer.timestamp(),
                    subtype, reason, matches.is_some(), ta, bssid, ra,
                    header.receiver_address.is_multicast(),
                    header.sequence_control.sequence_number(), header.sequence_control.fragment_number(),
                    header.fcf_flags.retry(), header.fcf_flags.protected(),
                    match self.rx_router_input.operation(RxRouterQueue::Foreground) {
                        None => "none",
                        Some(StaRxRouterOperation::Scanning) => "scan",
                        Some(StaRxRouterOperation::Authenticating { .. }) => "auth",
                        Some(StaRxRouterOperation::Associating { .. }) => "assoc",
                        Some(StaRxRouterOperation::CryptoHandshake { .. }) => "handshake",
                    },
                );
                borrowed_buffer.timestamp()
            });
            #[cfg(feature = "handshake-probe")]
            let probe_kind = if generic_frame.is_eapol_key_frame() { 1 } else {
                match generic_frame.frame_control_field().frame_type() {
                    FrameType::Management(ieee80211::common::ManagementFrameSubtype::Authentication) => 2,
                    FrameType::Management(ieee80211::common::ManagementFrameSubtype::AssociationResponse) => 3,
                    FrameType::Management(ieee80211::common::ManagementFrameSubtype::Deauthentication) => 4,
                    _ => 0,
                }
            };
            #[cfg(feature = "handshake-probe")]
            if probe_kind == 1 {
                if let Some(Ok(frame)) = generic_frame.parse_to_typed::<DataFrame>() {
                    if let Some(payload) = frame.payload {
                        // LLC (8), EAPOL header (4), descriptor type (1), flags (2).
                        // This is unverified metadata, never protocol input.
                        if payload.get(9) == Some(&3) {
                            if let Some(flags) = payload.get(13..15) {
                                crate::handshake_probe::event(10,
                                    u16::from_be_bytes([flags[0], flags[1]]) as u32,
                                    self.sta_tx_rx.connection_state.connected() as u32
                                        | ((frame.header.fcf_flags.retry() as u32) << 1));
                            }
                        }
                    }
                }
            }
            let _route_result = self.rx_router_input.route_frame(borrowed_buffer);
            #[cfg(feature = "handshake-probe")]
            crate::handshake_probe::routed(probe_kind, _route_result.is_ok(), self.rx_router_input.queue_lengths());
            #[cfg(feature = "connection-trace")]
            if let Some(rx_timestamp) = management_trace {
                log::info!(
                    "stage=sta_mgmt_route rx_timestamp={} queued={}",
                    rx_timestamp,
                    _route_result.is_ok()
                );
            }
        }
    }
}
/// Interface runner for the STA interface.
pub struct StaRunner<'foa, 'vif> {
    pub(crate) tx_runner: TxRunner<'vif, MTU>,
    pub(crate) connection_runner: ConnectionRunner<'foa, 'vif>,
    pub(crate) routing_runner: RoutingRunner<'foa, 'vif>,
}
impl StaRunner<'_, '_> {
    /// Run the station interface.
    pub fn run(&mut self) -> impl Future<Output = ()> {
        debug!("STA runner active.");
        join(
            self.connection_runner.run(&mut self.tx_runner),
            self.routing_runner.run(),
        )
        .map(|_| ())
    }
}
