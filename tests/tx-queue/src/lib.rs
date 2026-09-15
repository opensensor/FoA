#![allow(dead_code, unexpected_cfgs)]

#[macro_use]
extern crate log;

// Match FoA's default pool count. The queue itself and pool ownership are not mocked.
pub const TX_BUFFER_COUNT: usize = if cfg!(feature = "small-pool") { 3 } else { 8 };
pub const TX_BUFFER_SIZE: usize = 64;

#[path = "../../../foa/src/tx_buffer_management.rs"]
mod tx_buffer_management;
pub use tx_buffer_management::TxBuffer;
#[cfg(feature = "tx-probe")]
#[path = "../../../foa/src/tx_probe.rs"]
pub mod tx_probe;

mod tx_queue {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../foa/src/tx_queue.rs"
    ));

    #[cfg(test)]
    include!("queue_tests.rs");
}
