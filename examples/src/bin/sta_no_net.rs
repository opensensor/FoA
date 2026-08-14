#![no_std]
#![no_main]

use embassy_executor::Spawner;
use log::info;

use esp_hal::{interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};

use examples::{get_credentials, mk_static};
use foa::{FoAResources, FoARunner, VirtualInterface};
use foa_sta::{StaResources, StaRunner};

const SSID: &str = env!("SSID");

#[embassy_executor::task]
async fn foa_task(mut foa_runner: FoARunner<'static>) {
    foa_runner.run().await
}
#[embassy_executor::task]
async fn sta_task(mut sta_runner: StaRunner<'static, 'static>) {
    sta_runner.run().await
}
#[esp_rtos::main]
async fn main(spawner: Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_interrupt.software_interrupt0);

    let stack_resources = mk_static!(FoAResources, FoAResources::new());
    let ([sta_vif, ..], foa_runner) = foa::init(stack_resources, peripherals.WIFI);
    spawner.spawn(foa_task(foa_runner).unwrap());

    let sta_resources = mk_static!(StaResources<'static>, StaResources::default());
    let (mut sta_control, sta_runner, _net_device) = foa_sta::new_sta_interface(
        mk_static!(VirtualInterface<'static>, sta_vif),
        sta_resources,
    );
    spawner.spawn(sta_task(sta_runner).unwrap());

    let mac_address = sta_control.randomize_mac_address().unwrap();
    info!("Using MAC address: {:x?}", mac_address);

    sta_control
        .connect_by_ssid(SSID, None, get_credentials())
        .await
        .unwrap();
    info!(
        "Connected to {} with AID: {:?}",
        SSID,
        sta_control.get_aid().unwrap()
    );
    let _ = sta_control.disconnect().await;
    info!("Disconnected again.")
}
