# Hardware

The demo runs completely on **native_sim** (no hardware). A real board shows that the
same evidence chain works for a microcontroller build, and can publish live on stage.

## Supported boards (Zephyr v4.4.2, verified to build)

| Make variable | Hardware | Network | Notes |
| --- | --- | --- | --- |
| `BOARD=native_sim/native/64` (default) | none | host sockets (NSOS) | runtime demo, `make run` |
| `BOARD=w5500_evb_pico2/rp2350a/m33` | WIZnet W5500-EVB-Pico2 | W5500 Ethernet on board | recommended real board, no wiring |
| `BOARD=rpi_pico2/rp2350a/m33` | Raspberry Pi Pico 2 or pin-compatible RP2350 clone + W5500 module | W5500 via SPI | wiring below |

Both real boards use the RP2350 hardware TRNG for TLS, and their RAM use is about
125 KB of 520 KB.

A Pico 2 **without** a W5500 has no network interface; it builds, but cannot publish.
The Pico 2 W variant has Wi-Fi, but needs a binary radio firmware blob and depends on
venue Wi-Fi, so it is not used here.

## Wiring: Pico 2 (clone) + W5500 module

Same pins as the W5500-EVB-Pico2, so both builds behave the same.

| Pico 2 pin | W5500 module |
| --- | --- |
| GP16 (SPI0 RX) | MISO |
| GP17 (SPI0 CS) | CS / SCS |
| GP18 (SPI0 SCK) | SCLK |
| GP19 (SPI0 TX) | MOSI |
| GP20 | RST |
| GP21 | INT |
| 3V3(OUT) | 3.3V |
| GND | GND |

Use a W5500 module that runs from 3.3 V.

## Network on stage

Direct Ethernet cable from the board to the laptop, static addresses (no DHCP, no DNS):

- board `192.168.77.2/24` (set in `app/boards/*.conf`)
- laptop `192.168.77.1/24`, Mosquitto listening on port 8883

The device still verifies the broker certificate for the name `mosquitto`.
The broker setup for the real board is added when the hardware is available.

## Console and flashing

- Flashing: hold BOOTSEL while plugging in USB, then copy `zephyr.uf2` to the drive that
  appears. No debug probe needed.
- Log output goes to UART0 (GP0 TX, GP1 RX, 115200 baud). Reading it needs a 3.3 V
  USB-serial adapter or a Raspberry Pi Debug Probe.
