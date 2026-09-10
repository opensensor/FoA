# OpenSensor FoA

This is OpenSensor Engineering's independently maintained fork of
[esp32-open-mac/FoA](https://github.com/esp32-open-mac/FoA). The canonical repository
is [opensensor/FoA](https://github.com/opensensor/FoA).

**AI-assisted and AI-generated contributions are welcome.** See
[Contributing](CONTRIBUTING.md) for review and validation expectations. Submit
[issues](https://github.com/opensensor/FoA/issues) and [pull requests](https://github.com/opensensor/FoA/pulls) here.

The [OpenSensor ESP repository index](https://github.com/opensensor/esp-wifi-hal/blob/main/FORKS.md)
links the related driver, stack, register definitions and reverse-engineering tools.
Original history, credits and licenses are retained.

This fork initially preserves upstream code. The S3 results in the repository
index apply to the Rust driver's recorded dependencies; they do not establish
hardware validation of this repository's current default branch.

## Upstream documentation

The original documentation follows; its badges, release links and project status
refer to upstream unless explicitly identified as OpenSensor results.

# Ferris on Air

Ferris on Air (FoA) is an open source 802.11 stack for the ESP32 written in
async rust, with the work of the [esp32-open-mac](https://esp32-open-mac.be/)
project. The stack is intended to be used with [embassy](https://embassy.dev/)
and is still in very early stages of development. We do not claim to be Wi-Fi
certified, but implement the features specified by IEEE 802.11 to our best knowledge.

## Design

The main FoA crate acts as a multiplexer, that divides access to the hardware up
into a number of virtual interfaces (VIF's). These can then be passed to interface
implementations, like `foa_sta` or
[`foa_dswifi`](https://github.com/mjwells2002/foa_dswifi). These interface
implementations can coexist, enabling things like AP/STA operation in the future.

## Structure

The `foa` crate contains the LMAC, TX buffer management and RX ARC buffer management.
`foa_sta` contains a rudimentary implementation of a station interface.
`examples` contain a set of examples showing how to use different parts of the stack.

## Usage

For a concrete usage example, see `examples`. These examples can be run with
`./run_example.sh <EXAMPLE_NAME> <CHIP> [SSID] [LOG_LEVEL]`.

## Note

The docs sometimes contain anecdotes I left during coding, since I believe them
to be interesting.

## License

This project is licensed under Apache 2.0 or MIT at your option.
