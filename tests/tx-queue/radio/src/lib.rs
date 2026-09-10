//! Mock only the radio boundary. Queue, buffers and synchronization stay real.
use std::cell::{Cell, RefCell};
use std::future::poll_fn;
use std::task::{Poll, Waker};

pub mod ll {
    #[derive(Default)]
    pub struct EdcaAccessCategory;
    impl EdcaAccessCategory {
        pub fn hardware_slot(&self) -> usize {
            1
        }
    }
}
pub mod rates {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct TxPhyRate;
}
pub mod prelude {
    pub use super::TxQueueEndpoint;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TxError {
        AckTimeout,
    }
    #[derive(Default)]
    pub struct TxMacParameters;
    #[derive(Default)]
    pub struct TxPlcpParameters;
    pub enum TxErrorBehaviour<'a> {
        Drop,
        RetryUntil(u8),
        MultiRateRetry(&'a [super::rates::TxPhyRate]),
    }
}

#[derive(Default)]
pub struct Radio {
    result: Cell<Option<Result<u8, prelude::TxError>>>,
    waker: RefCell<Option<Waker>>,
    pub frames: RefCell<Vec<Vec<u8>>>,
    pub sequence_override: Cell<Option<u16>>,
}
impl Radio {
    pub fn complete(&self, result: Result<u8, prelude::TxError>) {
        self.result.set(Some(result));
        let waker = self.waker.borrow_mut().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

pub struct TxQueueEndpoint<'a> {
    radio: &'a Radio,
}
impl<'a> TxQueueEndpoint<'a> {
    pub fn new(radio: &'a Radio) -> Self {
        Self { radio }
    }
    pub fn hardware_tx_queue(&self) -> ll::EdcaAccessCategory {
        ll::EdcaAccessCategory
    }
    pub async fn transmit(
        &mut self,
        _: usize,
        _: &prelude::TxPlcpParameters,
        _: &prelude::TxMacParameters,
        _: prelude::TxErrorBehaviour<'_>,
        frame: &mut [u8],
    ) -> Result<u8, prelude::TxError> {
        if let Some(sequence) = self.radio.sequence_override.get() {
            if let Some(bytes) = frame.get_mut(22..24) {
                bytes.copy_from_slice(&(sequence << 4).to_le_bytes());
            }
        }
        self.radio.frames.borrow_mut().push(frame.to_vec());
        poll_fn(|cx| {
            if let Some(result) = self.radio.result.take() {
                Poll::Ready(result)
            } else {
                self.radio.waker.replace(Some(cx.waker().clone()));
                Poll::Pending
            }
        })
        .await
    }
    pub async fn transmit_oneshot(
        &mut self,
        interface: usize,
        plcp: &prelude::TxPlcpParameters,
        mac: &prelude::TxMacParameters,
        frame: &mut [u8],
    ) -> Result<(), prelude::TxError> {
        self.transmit(interface, plcp, mac, prelude::TxErrorBehaviour::Drop, frame)
            .await
            .map(|_| ())
    }
}
