#![no_std]
#![no_main]

use alloc::collections::btree_map::BTreeMap;
use embassy_executor::Spawner;
use log::info;

use esp_hal::{
    clock::CpuClock, interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup,
};

use examples::mk_static;
use foa::{FoAResources, FoARunner, VirtualInterface};
use foa_sta::{StaResources, StaRunner};

extern crate alloc;

#[embassy_executor::task]
async fn foa_task(mut runner: FoARunner<'static>) {
    runner.run().await
}
#[embassy_executor::task]
async fn sta_task(mut runner: StaRunner<'static, 'static>) {
    runner.run().await
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_interrupt.software_interrupt0);
    examples::init();

    let stack_resources = mk_static!(FoAResources, FoAResources::new());
    let ([sta_vif, ..], foa_runner) = foa::init(stack_resources, peripherals.WIFI);
    spawner.spawn(foa_task(foa_runner).unwrap());
    let sta_resources = mk_static!(StaResources, StaResources::default());
    let (mut sta_control, sta_runner, _net_device) = foa_sta::new_sta_interface(
        mk_static!(VirtualInterface<'static>, sta_vif),
        sta_resources,
    );
    spawner.spawn(sta_task(sta_runner).unwrap());
    info!("Starting scan.");
    let mut found_bss = BTreeMap::new();
    let _ = sta_control.scan_continuously(None, &mut found_bss, move |bss| {
        info!(
            "Found BSS, with SSID: \"{}\", BSSID: {}, channel: {}, last RSSI: {} Security: {:?}.",
            bss.ssid, bss.bssid, bss.channel, bss.last_rssi, bss.security_config
        );
        true
    }).await;
}
