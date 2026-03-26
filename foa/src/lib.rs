#![no_std]
#![deny(missing_docs)]
//! # Ferris-on-Air (FoA)
//! Ferris-on-Air is an asynchronous IEEE 802.11 MAC stack for the ESP32 series of chips. It is
//! build on top of [esp_wifi_hal], which is the driver for the Wi-Fi peripheral, and is based on
//! the reverse engineering efforts of the [ESP32-Open-MAC project](https://esp32-open-mac.be/).
//! ## Note:
//! This project is neither maintained by nor in anyway affiliated with Espressif. You're using
//! this at your own risk!
//! ## Structure
//! The `foa` crate is the central element of the stack. It doesn't implement any specific
//! operating modes, but implements the APIs to do so. When calling [init], you get a
//! [FoARunner] and a set of [VirtualInterfaces](VirtualInterface), which can then be passed on to
//! interface implementations.
//!
//! Currently, the following operating modes have an interface implemented for them.
//!
//! Operating Mode | Implementation | Description | Maintainer
//! -- | -- | -- | --
//! STA | [foa_sta](https://github.com/esp32-open-mac/FoA/tree/main/foa_sta) | A simple client implementation. | `Frostie314159`
//! Nintendo DS Pictochat | [foa_dswifi](https://github.com/mjwells2002/foa_dswifi) | An implementation of the Nintendo DS Pictochat protocol. | `mjwells2002`
//! AWDL | [foa_awdl](https://github.com/esp32-open-mac/FoA/tree/main/foa_awdl) | An implementation of the Apple Wireless Direct Link protocol | `Frostie314159`
//!
//!
//! ### Station (STA)
//! A simple STA mode interface is implemented in [foa_sta](https://github.com/esp32-open-mac/FoA/tree/main/foa_sta).
//! For details on the supported features, please check the documentation of `foa_sta`.

use core::{array, mem};

use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicReceiver},
    mutex::Mutex,
};
use esp_config::esp_config_int;
use esp_hal::peripherals::WIFI;
use esp_wifi_hal::prelude::*;
use lmac::SharedLMacState;

#[macro_use]
extern crate defmt_or_log;

mod bg_task;
mod lmac;
#[cfg(feature = "arc_buffers")]
mod rx_arc_pool;
mod tx_buffer_management;
mod tx_queue;

pub use bg_task::FoARunner;
pub use lmac::*;
use portable_atomic::AtomicBool;
#[cfg(feature = "arc_buffers")]
pub use rx_arc_pool::RxArcBuffer;
pub use tx_buffer_management::TxBuffer;
pub use tx_queue::{
    PendingTransmission, PendingTransmissionStatus, RetryBehaviour, TxEndpoint, TxReturnData,
};

pub use esp_wifi_hal;
#[cfg(feature = "arc_buffers")]
use rx_arc_pool::RxArcPool;
use tx_buffer_management::TxBufferManager;

use crate::{
    bg_task::{RxRunner, TxRunner},
    tx_queue::{TxQueue, TxQueueRunner},
};

pub mod util;

const RX_BUFFER_COUNT: usize = esp_config_int!(usize, "FOA_CONFIG_RX_BUFFER_COUNT");
const RX_QUEUE_LEN: usize = esp_config_int!(usize, "FOA_CONFIG_RX_QUEUE_LEN");
const TX_BUFFER_COUNT: usize = esp_config_int!(usize, "FOA_CONFIG_TX_BUFFER_COUNT");
/// The size of a [TxBuffer].
///
/// This is fixed, so that interfaces can rely on the size of a TX buffer.
pub const TX_BUFFER_SIZE: usize = 1600;

/// A frame received from the driver.
#[cfg(feature = "arc_buffers")]
pub type ReceivedFrame<'res> = RxArcBuffer<'res>;
#[cfg(not(feature = "arc_buffers"))]
/// A frame received from the driver.
pub type ReceivedFrame<'res> = BorrowedBuffer<'res>;
/// A receiver to the RX queue of an interface.
pub type RxQueueReceiver<'res> = DynamicReceiver<'res, ReceivedFrame<'res>>;

/// The resources required by the WiFi stack.
pub struct FoAResources {
    /// Resources for the Wi-Fi driver.
    wifi_resources: WiFiResources<RX_BUFFER_COUNT>,
    /// State for the LMAC.
    shared_lmac_state: Option<SharedLMacState>,

    // RX
    /// RX Queues for all interfaces.
    ///
    /// The [AtomicBool] indicates, whether this queue is active.
    rx_queues: [(
        Channel<NoopRawMutex, ReceivedFrame<'static>, RX_QUEUE_LEN>,
        AtomicBool,
    ); INTERFACE_COUNT],
    #[cfg(feature = "arc_buffers")]
    /// Atomically reference counted buffer pool.
    arc_pool: RxArcPool,

    // TX
    /// All EDCA TX queues.
    edca_tx_queues: Option<[TxQueue; 4]>,
    /// Beacon TX is handled differently, since it's essentially always bound to stricter timing
    /// requirements.
    beacon_tx_queue: Option<Mutex<NoopRawMutex, TxQueueEndpoint<'static>>>,
    /// TX buffers used by the [TxBufferManager].
    tx_buffers: [[u8; TX_BUFFER_SIZE]; TX_BUFFER_COUNT],
    /// The aforementioned TX buffer manager.
    tx_buffer_manager: Option<TxBufferManager<TX_BUFFER_COUNT>>,
}
impl FoAResources {
    /// Create new stack resources.
    ///
    /// This has to be in internal RAM, since the DMA descriptors and buffers for the Wi-Fi driver
    /// have to be in internal RAM.
    pub fn new() -> Self {
        Self {
            wifi_resources: WiFiResources::new(),
            #[cfg(feature = "arc_buffers")]
            arc_pool: RxArcPool::new(),
            rx_queues: [const { (Channel::new(), AtomicBool::new(true)) }; INTERFACE_COUNT],
            shared_lmac_state: None,

            edca_tx_queues: None,
            beacon_tx_queue: None,
            tx_buffers: [[0u8; TX_BUFFER_SIZE]; TX_BUFFER_COUNT],
            tx_buffer_manager: None,
        }
    }
}
impl Default for FoAResources {
    fn default() -> Self {
        Self::new()
    }
}

/// A virtual interface (VIF).
///
/// This is intended to be used by interface implementations, which should take in a mutable
/// reference to a VIF.
pub struct VirtualInterface<'res> {
    interface_control: LMacInterfaceControl<'res>,
    rx_queue_receiver: RxQueueReceiver<'res>,
    tx_endpoint: TxEndpoint<'res>,
}
impl<'res> VirtualInterface<'res> {
    /// Split the virtual interface into it's components.
    ///
    /// NOTE: This is intended for interface implementations. User code shouldn't call this,
    /// although nothing will happen.
    pub fn split<'a>(
        &'a mut self,
    ) -> (
        &'a mut LMacInterfaceControl<'res>,
        &'a mut RxQueueReceiver<'res>,
        &'a mut TxEndpoint<'res>,
    ) {
        (
            &mut self.interface_control,
            &mut self.rx_queue_receiver,
            &mut self.tx_endpoint,
        )
    }
    /// Reset the virtual interface.
    ///
    /// This is releases any prior channel lock, resets all filters and clears the RX queue.
    pub fn reset(&mut self) {
        // We can't call clear on a DynamicReceiver, so this is the best we can do for now.
        // This isn't too bad, since this will only be called rarely and the RX queues shouldn't be
        // that long.
        while self.rx_queue_receiver.try_receive().is_ok() {}
        self.interface_control.unlock_channel();
        self.interface_control
            .set_scanning_mode(ScanningMode::Disabled);
        self.interface_control.clear_filter(RxFilterBank::Bssid);
        self.interface_control
            .clear_filter(RxFilterBank::ReceiverAddress);
    }
}

/// Initialise FoA.
pub fn init<'res>(
    resources: &'res mut FoAResources,
    wifi: WIFI<'res>,
) -> ([VirtualInterface<'res>; INTERFACE_COUNT], FoARunner<'res>) {
    let wifi = WiFi::new(wifi, &mut resources.wifi_resources);

    let SplitDriverComponents {
        rx_interface_controllers,
        rx_endpoint,
        channel_controller,
        crypto_controller,
        tx_queue_endpoints: [beacon_tx_endpoint, edca_tx_endpoints @ ..],
    } = wifi.split();

    // This is for all transmutes here.
    // # SAFETY:
    // We do this only to avoid self referential structs. All of the destination lifetimes are the
    // lifetime of the resources struct and therefore valid.

    // Initialize global state
    let shared_lmac_state = resources
        .shared_lmac_state
        .insert(SharedLMacState::new(channel_controller, crypto_controller));
    let tx_buffer_manager = resources
        .tx_buffer_manager
        .insert(unsafe { TxBufferManager::new(&mut resources.tx_buffers) });
    let lmac_interface_controls = shared_lmac_state.split(rx_interface_controllers);
    let rx_queue_senders = array::from_fn(|i| {
        (
            unsafe { mem::transmute(resources.rx_queues[i].0.dyn_sender()) },
            &resources.rx_queues[i].1,
        )
    });
    // TX queue setup
    let beacon_tx_queue = resources.beacon_tx_queue.insert(Mutex::new(unsafe {
        core::mem::transmute(beacon_tx_endpoint)
    }));
    let edca_tx_queues = resources
        .edca_tx_queues
        .insert([const { TxQueue::new() }; 4]);
    let edca_tx_queues = unsafe {
        core::mem::transmute::<&mut [TxQueue; 4], &'res mut [TxQueue; 4]>(edca_tx_queues)
    };

    let virtual_interfaces = unsafe {
        lmac_interface_controls.map(|lmac_interface_control| VirtualInterface {
            rx_queue_receiver: mem::transmute(
                resources.rx_queues[lmac_interface_control.interface()]
                    .0
                    .dyn_receiver(),
            ),
            tx_endpoint: mem::transmute(TxEndpoint {
                beacon_tx_endpoint: &beacon_tx_queue,
                dyn_tx_buffer_manager: tx_buffer_manager.dyn_tx_buffer_manager(),
                edca_tx_endpoints: edca_tx_queues.each_ref(),
                interface: lmac_interface_control.interface(),
            }),
            interface_control: lmac_interface_control,
        })
    };

    (
        virtual_interfaces,
        FoARunner {
            tx_runner: TxRunner {
                edca_tx_runners: edca_tx_endpoints.map(|tx_endpoint| TxQueueRunner {
                    tx_queue: &edca_tx_queues[tx_endpoint.hardware_tx_queue().hardware_slot() - 1],
                    tx_endpoint,
                }),
            },
            rx_runner: RxRunner {
                rx_endpoint,
                rx_queue_senders,
                #[cfg(feature = "arc_buffers")]
                rx_arc_pool: &resources.arc_pool,
            },
        },
    )
}
