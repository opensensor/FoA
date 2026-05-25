#![no_std]

extern crate alloc;

use foa_sta::Credentials;

use esp_backtrace as _;
use esp_println as _;

pub fn init() {
    esp_alloc::heap_allocator!(size: 40 * 1024);
    esp_bootloader_esp_idf::esp_app_desc!();
}

pub fn get_credentials() -> Option<Credentials<'static>> {
    option_env!("PASSWORD").map (Credentials::Passphrase)
}
#[macro_export]
macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.init_with(|| ($val));
        x
    }};
}
