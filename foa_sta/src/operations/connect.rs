use core::{marker::PhantomData, mem};

use embassy_futures::join::join;
use embassy_time::WithTimeout;
use foa::{
    ReceivedFrame, TxBuffer,
    esp_wifi_hal::{
        ll::EdcaAccessCategory,
        prelude::{RxFilterBank, TxMacParameters, TxPlcpParameters},
    },
};
use ieee80211::{
    common::{
        AssociationID, CapabilitiesInformation, IEEE80211AuthenticationAlgorithmNumber,
        IEEE80211StatusCode, SequenceControl,
    },
    element_chain,
    elements::{SSIDElement, rsn::RsnElement},
    mac_parser::MACAddress,
    mgmt_frame::{
        AssociationRequestFrame, AssociationResponseFrame, AuthenticationFrame,
        ManagementFrameHeader,
        body::{AssociationRequestBody, AuthenticationBody},
    },
    scroll::{Pread, Pwrite},
};

use crate::{
    ConnectionConfig, SecurityConfig, StaError, StaTxRx,
    bss::BSS,
    operations::{DEFAULT_SUPPORTED_RATES, DEFAULT_XRATES},
    rx_router::{
        StaRxRouterEndpoint, StaRxRouterOperation, StaRxRouterScopedOperation,
        receive_connection_response,
    },
    util::HexWrapper,
};

pub struct ConnectionParameters<'a> {
    pub config: ConnectionConfig,
    pub own_address: MACAddress,
    #[allow(unused)]
    pub credentials: Option<crate::Credentials<'a>>,
}

/// Connecting to an AP.
struct ConnectionOperation<'foa, 'vif, 'params> {
    sta_tx_rx: &'params StaTxRx<'foa, 'vif>,
    connection_parameters: &'params ConnectionParameters<'params>,
}
macro_rules! probe_phase {
    ($phase:expr) => { #[cfg(feature = "handshake-probe")] crate::handshake_probe::phase($phase); };
}
macro_rules! probe_event {
    ($kind:expr, $a:expr, $b:expr) => {
        #[cfg(feature = "handshake-probe")]
        crate::handshake_probe::event($kind, $a, $b);
    };
}
#[cfg(feature = "rsn")]
pub(crate) use private::send_message_4;
#[cfg(feature = "rsn")]
mod private {
    use core::marker::PhantomData;

    use foa::{
        RetryBehaviour, TxBuffer, TxReturnData,
        esp_wifi_hal::{
            ll::EdcaAccessCategory,
            prelude::{TxMacParameters, TxPlcpParameters},
        },
    };
    use ieee80211::{
        common::{DataFrameSubtype, FCFFlags, SequenceControl},
        crypto::{
            derive_ptk,
            eapol::{EapolKeyFrame, KeyDescriptorVersion, KeyInformation},
            partition_ptk, serialize_eapol_data_frame,
        },
        data_frame::{DataFrame, header::DataFrameHeader},
        element_chain,
        elements::{
            rsn::{IEEE80211CipherSuiteSelector, RsnElement},
        },
        mac_parser::MACAddress,
        scroll::{self, ctx::TryIntoCtx},
    };
    use llc_rs::{EtherType, SnapLlcFrame};

    use crate::{
        BSS, StaError, StaTxRx,
        rsn::{
            GTK_LENGTH, PMK_LENGTH, PTK_LENGTH, SecurityAssociations,
            TransientKeySecurityAssociation, WPA2_PSK_AKM,
        },
        rx_router::{StaRxRouterOperation, StaRxRouterScopedOperation},
        util::HexWrapper,
    };

    pub(crate) async fn send_message_4(
        sta_tx_rx: &StaTxRx<'_, '_>,
        bssid: MACAddress,
        own_address: MACAddress,
        kck: &[u8; 16],
        supplicant_nonce: &[u8; 32],
        key_replay_counter: u64,
    ) -> Result<(), StaError> {
        super::ConnectionOperation::send_eapol_key_frame(
            sta_tx_rx,
            bssid,
            own_address,
            EapolKeyFrame {
                key_information: KeyInformation::new()
                    .with_is_pairwise(true)
                    .with_key_mic(true)
                    .with_secure(true)
                    .with_key_descriptor_version(KeyDescriptorVersion::AesHmacSha1),
                key_length: 16,
                key_replay_counter,
                key_nonce: *supplicant_nonce,
                key_mic: [0x00u8; WPA2_PSK_AKM.key_mic_len().unwrap()].as_slice(),
                key_data: element_chain! {},
                ..Default::default()
            },
            Some(kck),
            None,
        )
        .await
    }
    impl<'foa, 'vif, 'params> super::ConnectionOperation<'foa, 'vif, 'params> {
        /// Transmit an EAPOL key frame, with the specified parameters.
        pub(crate) async fn send_eapol_key_frame<
            'a,
            KeyMic: AsRef<[u8]>,
            ElementContainer: TryIntoCtx<(), Error = scroll::Error>,
        >(
            sta_tx_rx: &StaTxRx<'_, '_>,
            bssid: MACAddress,
            own_address: MACAddress,
            payload: EapolKeyFrame<'a, KeyMic, ElementContainer>,
            kck: Option<&[u8; 16]>,
            kek: Option<&[u8; 16]>,
        ) -> Result<(), StaError> {
            let data_frame = DataFrame {
                header: DataFrameHeader {
                    subtype: DataFrameSubtype::Data,
                    fcf_flags: FCFFlags::new().with_to_ds(true),
                    address_1: bssid,
                    address_2: own_address,
                    address_3: bssid,
                    sequence_control: SequenceControl::new(),
                    ..Default::default()
                },
                payload: Some(SnapLlcFrame {
                    oui: [0u8; 3],
                    ether_type: EtherType::Eapol,
                    payload,
                    _phantom: PhantomData,
                }),
                _phantom: PhantomData,
            };
            let mut tx_buffer = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
            let (buffer, temp_buffer) = tx_buffer.split_at_mut(500);
            let written =
                serialize_eapol_data_frame(kck, kek, data_frame, buffer, temp_buffer).unwrap();
            let res = sta_tx_rx
                .tx_endpoint
                .transmit_edca(
                    EdcaAccessCategory::default(),
                    tx_buffer,
                    written,
                    TxPlcpParameters {
                        rate: sta_tx_rx.phy_rate(),
                        ..Default::default()
                    },
                    TxMacParameters {
                        // The EAPOL data header starts with a placeholder.
                        override_seq_num: true,
                        ..Default::default()
                    },
                    RetryBehaviour::RetryUntil(7),
                )
                .wait_for_completion()
                .await;
            probe_event!(8, match &res { Some(r) if r.result.is_ok() => 0, Some(_) => 1, None => 2 }, 0);
            if matches!(res, Some(TxReturnData { result: Err(_), .. })) {
                debug!("4WHS step timeout.");
                Err(StaError::AckTimeout)
            } else {
                Ok(())
            }
        }
        /// Wait for a bounded M1 envelope from the selected AP.
        async fn process_message_1(
            &self,
            router_operation: &StaRxRouterScopedOperation<'foa, 'vif, 'params>,
            bss: &BSS,
        ) -> crate::rsn_initial::InitialHandshake {
            loop {
                let frame = router_operation.receive().await;
                if let Some(pending) = crate::rsn_initial::InitialHandshake::from_message_1(
                    frame.mpdu_buffer(), self.connection_parameters.own_address, bss.bssid,
                ) {
                    probe_event!(2, 0x008a, 0);
                    return pending;
                }
                probe_event!(3, 2, 0);
            }
        }
        fn send_message_2(
            &self,
            bss: &'params BSS,
            kck: &[u8; 16],
            supplicant_nonce: &[u8; 32],
            key_replay_counter: u64,
        ) -> impl Future<Output = Result<(), StaError>> {
            Self::send_eapol_key_frame(
                self.sta_tx_rx,
                bss.bssid,
                self.connection_parameters.own_address,
                EapolKeyFrame {
                    key_information: KeyInformation::new()
                        .with_is_pairwise(true)
                        .with_key_mic(true)
                        .with_key_descriptor_version(KeyDescriptorVersion::AesHmacSha1),
                    key_length: 16,
                    key_replay_counter,
                    key_nonce: *supplicant_nonce,
                    key_mic: [0x00u8; WPA2_PSK_AKM.key_mic_len().unwrap()].as_slice(),
                    key_data: element_chain! {
                        RsnElement::WPA2_PERSONAL
                    },
                    ..Default::default()
                },
                Some(kck),
                None,
            )
        }
        async fn process_message_3(
            &self,
            router_operation: &StaRxRouterScopedOperation<'foa, 'vif, 'params>,
            mut scratch_buffer: TxBuffer<'_>,
            bss: &'params BSS,
            kck: &[u8; 16],
            kek: &[u8; 16],
            supplicant_nonce: &[u8; 32],
            pending: &mut crate::rsn_initial::InitialHandshake,
        ) -> Result<TransientKeySecurityAssociation<GTK_LENGTH, false>, StaError> {
            loop {
                let mut frame = router_operation.receive().await;
                if let Some(counter) = pending.message_1_retry(
                    frame.mpdu_buffer(), self.connection_parameters.own_address, bss.bssid,
                ) {
                    // Return the RX buffer before awaiting another transmission.
                    drop(frame);
                    probe_event!(14, 1, 0);
                    let result = self.send_message_2(bss, kck, supplicant_nonce, counter).await;
                    probe_event!(15, if result.is_ok() { 0 } else { 1 }, 0);
                    result?;
                    continue;
                }
                if let Some(key) = pending.message_3(
                    frame.mpdu_buffer_mut(), scratch_buffer.as_mut_slice(), kck, kek,
                    self.connection_parameters.own_address, bss.bssid,
                ) {
                    probe_event!(4, 0x13ca, 0);
                    return Ok(TransientKeySecurityAssociation::new(key.gtk, key.gtk_id));
                }
                probe_event!(5, 2, 0);
            }
        }
        fn send_message_4(
            &self,
            bss: &'params BSS,
            kck: &[u8; 16],
            supplicant_nonce: &[u8; 32],
            key_replay_counter: u64,
        ) -> impl Future<Output = Result<(), StaError>> {
            send_message_4(self.sta_tx_rx, bss.bssid,
                self.connection_parameters.own_address, kck, supplicant_nonce, key_replay_counter)
        }
        pub(super) async fn do_4whs(
            &self,
            pmk: [u8; PMK_LENGTH],
            router_operation: &mut StaRxRouterScopedOperation<'foa, 'vif, 'params>,
            bss: &'params BSS,
        ) -> Result<(SecurityAssociations, crate::rsn_retransmit::Message3Replay), StaError> {
            use esp_hal::rng::Rng;

            router_operation.transition(
            StaRxRouterOperation::CryptoHandshake{
                own_address: self.connection_parameters.own_address
            })
            .expect("This should not fail, since all three connecting operations have the same compatibility and there is no await point in the transition.");

            let mut supplicant_nonce = [0u8; 32];
            Rng::new().read(&mut supplicant_nonce);
            debug!(
                "Starting 4WHS. PMK: {}; SNonce: {}",
                HexWrapper(&pmk),
                HexWrapper(&supplicant_nonce)
            );

            probe_phase!(5);
            let mut pending = self.process_message_1(router_operation, bss).await;
            let authenticator_nonce = pending.authenticator_nonce;
            debug!(
                "Processed 4WHS message 1. ANonce: {}",
                HexWrapper(&authenticator_nonce)
            );

            probe_phase!(6);
            let mut ptk = TransientKeySecurityAssociation::new([0u8; PTK_LENGTH], 0);
            derive_ptk(
                &pmk,
                &bss.bssid,
                &self.connection_parameters.own_address,
                &authenticator_nonce,
                &supplicant_nonce,
                &mut ptk.key,
            );
            let (kck, kek, tk) = partition_ptk(
                &ptk.key,
                WPA2_PSK_AKM,
                IEEE80211CipherSuiteSelector::Ccmp128,
            )
            .unwrap();
            let (kck, kek): ([u8; 16], [u8; 16]) =
                (kck.try_into().unwrap(), kek.try_into().unwrap());
            debug!(
                "Derived PTK. KCK: {} KEK: {}, TK: {}",
                HexWrapper(&kck),
                HexWrapper(&kek),
                HexWrapper(tk)
            );
            probe_phase!(7);
            self.send_message_2(bss, &kck, &supplicant_nonce, pending.replay_counter)
                .await?;
            debug!("Sent 4WHS message 2.");

            // We abuse a TX buffer as a general purpose buffer here.
            let scratch_buffer = self.sta_tx_rx.tx_endpoint.alloc_tx_buf().await;

            probe_phase!(8);
            let gtk = self.process_message_3(
                router_operation, scratch_buffer, bss, &kck, &kek,
                &supplicant_nonce, &mut pending,
            ).await?;
            debug!(
                "Processed 4WHS message 3. GTK: {} GTK Key ID: {}",
                HexWrapper(&gtk.key),
                gtk.key_id
            );

            probe_phase!(9);
            self.send_message_4(bss, &kck, &supplicant_nonce, pending.replay_counter)
                .await?;
            debug!("Sent 4WHS message 4.");

            Ok((SecurityAssociations {
                ptksa: ptk,
                gtksa: gtk,
                akm_suite: WPA2_PSK_AKM,
                cipher_suite: IEEE80211CipherSuiteSelector::Ccmp128,
            }, crate::rsn_retransmit::Message3Replay::new(
                authenticator_nonce, supplicant_nonce, pending.replay_counter,
            )))
        }
    }
}
impl<'foa, 'vif, 'params> ConnectionOperation<'foa, 'vif, 'params> {
    fn complete(self) {
        mem::forget(self);
    }
    /// Send the specified frame and wait for a response.
    ///
    /// If no response is received in the specified timeout duration, or a transmission error
    /// occurs, the step will be retried as many times as specified. This compensates for a weird
    /// behavior of some APs, where they ACK a frame, but don't transmit a response. While this is
    /// rare, it can still occur, so this significantly stabilizes connection establishment.
    async fn do_bidirectional_connection_step(
        &self,
        router_operation: &StaRxRouterScopedOperation<'foa, 'vif, 'params>,
        mut frame: TxBuffer<'foa>,
        frame_length: usize,
    ) -> Result<ReceivedFrame<'_>, StaError> {
        for _ in 0..=self.connection_parameters.config.handshake_retries {
            let Some(res) = self
                .sta_tx_rx
                .tx_endpoint
                .transmit_edca(
                    EdcaAccessCategory::default(),
                    frame,
                    frame_length,
                    TxPlcpParameters {
                        rate: self.sta_tx_rx.phy_rate(),
                        ..Default::default()
                    },
                    TxMacParameters {
                        // Authentication and association frames are generated
                        // here; assign a new sequence for each queued request.
                        override_seq_num: true,
                        ..Default::default()
                    },
                    foa::RetryBehaviour::RetryUntil(7),
                )
                .wait_for_completion()
                .await
            else {
                warn!("Somehow the queue overran this shouldn't be possible.");
                break;
            };
            frame = res.frame;
            // Revalidate against the current operation: a response queued before
            // an auth/assoc transition may have the previous step's subtype.
            // One timeout covers all discarded frames, preserving the deadline.
            if let Ok(frame) = receive_connection_response(router_operation)
                .with_timeout(self.connection_parameters.config.handshake_timeout)
                .await
            {
                return Ok(frame);
            } else {
                trace!("Response to bidirectional connection step timed out.");
                continue;
            };
        }
        Err(StaError::ResponseTimeout)
    }
    /// Authenticate with the BSS.
    ///
    /// This currently only performs open system authentication.
    async fn do_auth(
        &self,
        router_operation: &StaRxRouterScopedOperation<'foa, 'vif, 'params>,
        bss: &BSS,
    ) -> Result<(), StaError> {
        let auth_frame = AuthenticationFrame {
            header: ManagementFrameHeader {
                receiver_address: bss.bssid,
                bssid: bss.bssid,
                transmitter_address: self.connection_parameters.own_address,
                sequence_control: SequenceControl::new(),
                duration: 0,
                ..Default::default()
            },
            body: AuthenticationBody {
                status_code: IEEE80211StatusCode::Success,
                authentication_algorithm_number: IEEE80211AuthenticationAlgorithmNumber::OpenSystem,
                authentication_transaction_sequence_number: 1,
                elements: element_chain! {},
                _phantom: PhantomData,
            },
        };
        // Allocate a TX buffer and serialize the frame.
        let mut tx_buffer = self.sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let written = tx_buffer.pwrite(auth_frame, 0).unwrap();
        // Transmit an authentication frame and wait for the response.
        let response = self
            .do_bidirectional_connection_step(router_operation, tx_buffer, written)
            .await?;
        // Try to parse the frame or return an error.
        let Ok(auth_frame) = response.mpdu_buffer().pread::<AuthenticationFrame>(0) else {
            debug!(
                "Failed to authenticate with {}, frame deserialization failed.",
                bss.bssid
            );
            return Err(StaError::FrameDeserializationFailed);
        };
        // Check if the authentication was successful and return an authentication failure if not.
        if auth_frame.status_code == IEEE80211StatusCode::Success {
            debug!("Successfully authenticated with {}.", bss.bssid);
            Ok(())
        } else {
            debug!(
                "Failed to authenticate with {}, status: {:?}.",
                bss.bssid, auth_frame.status_code
            );
            Err(StaError::AuthenticationFailure(auth_frame.status_code))
        }
    }
    /// Associate with the BSS.
    ///
    /// Like authentication, this only performs the bare minimum with a set of predetermined
    /// supported rates.
    async fn do_assoc(
        &self,
        router_operation: &mut StaRxRouterScopedOperation<'foa, 'vif, 'params>,
        bss: &BSS,
    ) -> Result<AssociationID, StaError> {
        router_operation.transition(
            StaRxRouterOperation::Associating {
                own_address: self.connection_parameters.own_address
            })
            .expect("This should not fail, since all three connecting operations have the same compatibility and there is no await point in the transition.");

        let rsn_active = bss.security_config != SecurityConfig::Open;
        let mut tx_buffer = self.sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let mut assoc_request_frame = AssociationRequestFrame {
            header: ManagementFrameHeader {
                receiver_address: bss.bssid,
                bssid: bss.bssid,
                transmitter_address: self.connection_parameters.own_address,
                sequence_control: SequenceControl::new(),
                duration: 60,
                ..Default::default()
            },
            body: AssociationRequestBody {
                capabilities_info: CapabilitiesInformation::new()
                    .with_is_ess(true)
                    .with_is_confidentiality_required(rsn_active),
                listen_interval: 0,
                elements: element_chain! {
                    SSIDElement::new(bss.ssid.as_str()).ok_or(StaError::InvalidBss)?,
                    DEFAULT_SUPPORTED_RATES,
                    DEFAULT_XRATES
                },
                _phantom: PhantomData,
            },
        }
        .into_dynamic(tx_buffer.as_mut())
        .unwrap();

        if rsn_active {
            assoc_request_frame
                .add_element(RsnElement::WPA2_PERSONAL)
                .unwrap();
        }

        let written = assoc_request_frame.finish(false).unwrap();
        // Transmit an association request and wait for the association response.
        let response = self
            .do_bidirectional_connection_step(router_operation, tx_buffer, written)
            .await?;
        // Try to parse the response or return an error.
        let Ok(assoc_response) = response.mpdu_buffer().pread::<AssociationResponseFrame>(0) else {
            debug!(
                "Failed to associate with {}, frame deserialization failed.",
                bss.bssid
            );
            return Err(StaError::FrameDeserializationFailed);
        };
        if let Some(aid) = assoc_response.association_id
            && assoc_response.status_code == IEEE80211StatusCode::Success
        {
            debug!(
                "Successfully associated with {}, AID: {:?}.",
                bss.bssid, aid
            );
            return Ok(aid);
        }
        debug!(
            "Failed to associate with {}, status: {:?}.",
            bss.bssid, assoc_response.status_code
        );
        debug!("Assoc frame: {}", HexWrapper(response.mpdu_buffer()));
        Err(StaError::AssociationFailure(assoc_response.status_code))
    }
    fn configure_rx_filters(&self, bss: &BSS) {
        // Here we set and enable the BSSID and RA filters.

        self.sta_tx_rx.interface_control.set_filter(
            RxFilterBank::ReceiverAddress,
            *self.connection_parameters.own_address,
        );
        self.sta_tx_rx
            .interface_control
            .set_filter(RxFilterBank::Bssid, *bss.bssid);
    }
    async fn run(
        self,
        rx_router_endpoint: &'params mut StaRxRouterEndpoint<'foa, 'vif>,
        bss: &BSS,
    ) -> Result<AssociationID, StaError> {
        #[cfg(feature = "handshake-probe")]
        crate::handshake_probe::reset();
        probe_phase!(0);
        probe_event!(9, rx_router_endpoint.queue_lengths()[0] as u32, rx_router_endpoint.queue_lengths()[1] as u32);
        debug!(
            "Connecting to {} on channel {} with MAC address {}.",
            bss.bssid, bss.channel, self.connection_parameters.own_address
        );
        // Start the bringup operation for LMAC channel lock.
        let bringup_operation = self
            .sta_tx_rx
            .interface_control
            .begin_interface_bringup_operation(bss.channel)
            .map_err(StaError::LMacError)?;

        // Start the RX router operation, so that authentication and association frames are routed
        // to us for the duration of the connection bringup.
        // NOTE: If further protocol negotiations, like RSN, TDLS, FT etc. are added in the future,
        // the match statement in the RX router will have to be expanded, to route those frames
        // too.
        let (mut router_operation, _) = join(
            rx_router_endpoint.start_operation(StaRxRouterOperation::Authenticating {
                own_address: self.connection_parameters.own_address,
            }),
            self.sta_tx_rx
                .interface_control
                .wait_for_off_channel_completion(),
        )
        .await;

        #[cfg(feature = "rsn")]
        let pmk_and_key_slots = if bss.security_config != SecurityConfig::Open
            && let Some(credentials) = self.connection_parameters.credentials
        {
            let [gtk_key_slot, ptk_key_slot] = core::array::from_fn(|_| {
                self.sta_tx_rx
                    .interface_control
                    .acquire_key_slot()
                    .ok_or(StaError::NoKeySlotsAvailable)
            });
            probe_phase!(1);
            let mut pmk = [0u8; crate::rsn::PMK_LENGTH];
            if credentials.pmk(&mut pmk, bss.ssid.as_str()).is_err() {
                debug!("Invalid PSK length.");
                return Err(StaError::InvalidPskLength);
            }
            probe_phase!(2);
            Some((pmk, gtk_key_slot?, ptk_key_slot?))
        } else {
            None
        };

        // Configure the RX filters to the specified addresses, so that we actually receive frames
        // from the AP.
        self.configure_rx_filters(bss);

        // Try to authenticate with the AP.
        probe_phase!(3);
        self.do_auth(&router_operation, bss).await?;

        // Try to associate with the AP.
        probe_phase!(4);
        let aid = self.do_assoc(&mut router_operation, bss).await?;

        #[cfg(feature = "rsn")]
        if let Some((pmk, gtk_key_slot, ptk_key_slot)) = pmk_and_key_slots {
            let (crypto_keys, message3_replay) = self.do_4whs(pmk, &mut router_operation, bss).await?;
            probe_phase!(10);
            self.sta_tx_rx.crypto_state.lock(|rc| {
                let _ = rc.borrow_mut().insert(crate::rsn::CryptoState::new(
                    gtk_key_slot,
                    ptk_key_slot,
                    *bss.bssid,
                    crypto_keys,
                    message3_replay,
                ));
            })
        }

        // By marking the connection operation as completed, we forget self and therefore the drop
        // code never gets executed and the filter configuration remains in place.
        self.complete();
        router_operation.complete();
        bringup_operation.complete();

        Ok(aid)
    }
}
impl Drop for ConnectionOperation<'_, '_, '_> {
    fn drop(&mut self) {
        self.sta_tx_rx
            .interface_control
            .clear_filter(RxFilterBank::ReceiverAddress);
        self.sta_tx_rx
            .interface_control
            .clear_filter(RxFilterBank::Bssid);
    }
}
pub fn connect<'foa, 'vif, 'params>(
    sta_tx_rx: &'params StaTxRx<'foa, 'vif>,
    rx_router_endpoint: &'params mut StaRxRouterEndpoint<'foa, 'vif>,
    bss: &'params BSS,
    connection_parameters: &'params ConnectionParameters<'params>,
) -> impl Future<Output = Result<AssociationID, StaError>> {
    ConnectionOperation {
        sta_tx_rx,
        connection_parameters,
    }
    .run(rx_router_endpoint, bss)
}
