# RP2040 Post-Quantum & Classical FIDO2 / WebAuthn Authenticator

A fully featured **FIDO2 / CTAP2.1 (WebAuthn)** hardware security key firmware for the **Raspberry Pi RP2040** microcontroller (tailored for the compact USB-A dongle [Waveshare RP2040-One](https://www.waveshare.com/wiki/RP2040-One)).

This project implements complete **Post-Quantum Cryptography (PQC)** support conforming to the latest finalized NIST standards (**FIPS 204** and **FIPS 203**), alongside classical high-assurance elliptic curve cryptography (NIST P-521 / ES512 and P-256 / ES256).

---

## Table of Contents
1. [Key Features](#1-key-features)
2. [Hardware Platform: Waveshare RP2040-One](#2-hardware-platform-waveshare-rp2040-one)
3. [Cryptographic Architecture & Algorithms](#3-cryptographic-architecture--algorithms)
4. [Credential Storage Architecture (Key Wrapping & Passkeys)](#4-credential-storage-architecture-key-wrapping--passkeys)
5. [Hardware User Presence (UP)](#5-hardware-user-presence-up)
6. [Hardware Status LED Indicator (WS2812 RGB)](#6-hardware-status-led-indicator-ws2812-rgb)
7. [BOOTSEL Programming Modes & Firmware Flashing](#7-bootsel-programming-modes--firmware-flashing)
8. [Building and Flashing](#8-building-and-flashing)
9. [WebAuthn Compatibility & Verification](#9-webauthn-compatibility--verification)
10. [Project Directory Layout](#10-project-directory-layout)

---

## 1. Key Features

* **Post-Quantum Signatures (FIPS 204)**: Complete implementation of **ML-DSA-87** (Dilithium-5) for credential creation (`MakeCredential`) and authentication assertions (`GetAssertion`).
* **Post-Quantum Key Encapsulation (FIPS 203)**: Implementation of **ML-KEM-1024** (Kyber-1024) for session key agreement in CTAP2.1 `pinUvAuthProtocol` 3.
* **Full IANA & RFC 9964 Compliance**: Encodes PQC public key metadata using the official standard `COSEKey` format (AKP, `kty: 7`, `alg: -50`, `PUB = -1`), guaranteeing out-of-the-box compatibility with modern Relying Party backends (including `webauthn.io` / `py_webauthn`).
* **Hardware Overclocking to 200 MHz**: Accelerates liboqs polynomial arithmetic by more than **3.3x** (reducing ML-DSA-87 assertion time from 7.4 s down to **~2.2 s**).
* **Infinite Accounts via Stateless Key Wrapping**: Private credentials do not consume on-chip Flash memory. Instead, they are authenticated and encrypted using an on-chip Master Key (AES-256-CBC + HMAC-SHA256) and stored on Relying Party servers.
* **Physical User Presence (UP)**: High-speed polling (500 Hz / 2 ms) of the onboard BOOTSEL button directly over the QSPI Flash interface without interfering with XIP execution.
* **Browser Timeout Prevention (CTAPHID Keepalive)**: Automatically dispatches `CTAPHID_CMD_KEEPALIVE` packets (`STATUS_UPNEEDED`) every 100 ms while awaiting touch, keeping browser dialogs active up to 30 seconds.
* **Interrupt-Driven LED State Machine**: The onboard WS2812 LED is smoothly animated via a 33.3 Hz hardware timer interrupt and never freezes, even during heavy liboqs polynomial computations.
* **USB Composite Device**: Functions concurrently as a FIDO2 CTAPHID device (Interface 0) and a USB CDC Serial Debug Console (Interfaces 1 & 2).

---

## 2. Hardware Platform: Waveshare RP2040-One

The firmware is optimized specifically for the miniature USB-A dongle **Waveshare RP2040-One**:
* **MCU**: Raspberry Pi RP2040 (Dual ARM Cortex-M0+ @ 200 MHz).
* **Flash**: 4 MB Quad-SPI NOR Flash (Winbond).
* **Pushbuttons**: 
  - `BOOT` (BOOTSEL) — wired to the `QSPI_CS` pin with a 10 kΩ pull-up resistor. Serves as the tactile User Presence confirmation button and enables emergency reboot into bootloader mode when held for > 2 s.
  - `RESET` — hardware microcontroller reset.
* **Status LED**: Onboard miniature addressable SMD LED WS2812B (2020 package) on **GPIO 16** (color byte order: **RGB**).
* **Form Factor**: Direct-plug USB Type-A PCB connector.

---

## 3. Cryptographic Architecture & Algorithms

The authenticator provides a dual-stack cryptographic engine supporting cutting-edge PQC and high-security classical elliptic curves.

| Class | Algorithm | Standard | COSE ID | `kty` | Role | Execution Time (@200 MHz) |
|---|---|---|---|---|---|---|
| **PQC** | **ML-DSA-87** (Dilithium-5) | FIPS 204 / RFC 9964 | `-50` | `7` (AKP) | Attestation & Assertion signatures | **2.20 s** (assert) / 4.40 s (keygen) |
| **PQC** | **ML-DSA-87** (Compat) | SandboxAQ draft | `-20` | `5` (LWE) | Backward compatibility with early drafts | **2.20 s** |
| **PQC** | **ML-KEM-1024** (Kyber-1024) | FIPS 203 | `-24` | `4` (KEM) | CTAP2.1 PIN/UV key exchange (Protocol 3) | **0.28 s** |
| **ECC** | **ECDSA secp521r1** (P-521) | FIPS 186-4 | `-36` (ES512) | `2` (EC2) | Maximum-security classical signatures | 2.70 s (assert) / 5.20 s (keygen) |
| **ECC** | **ECDH secp521r1** (P-521) | NIST SP 800-56A | `-25`, `-29` | `2` (EC2) | Classical ClientPIN key exchange | 0.15 s |
| **ECC** | **ECDSA secp256r1** (P-256) | FIPS 186-4 | `-7` (ES256) | `2` (EC2) | Standard browser compatibility | **0.05 s** |

### Deterministic PQC Key Derivation (`keypair_internal`)
Standard ML-DSA key generation uses random entropy to produce a 4896-byte secret key. Storing keys of this magnitude inside credential handles is impractical on embedded hardware. Therefore, the firmware derives the keypair deterministically on the fly from a 32-byte credential seed (`cred_seed`):
```c
// Internal deterministic keypair derivation per FIPS 204:
PQCP_MLDSA_NATIVE_MLDSA87_C_keypair_internal(pk, sk, cred_seed);
```
During authentication (`GetAssertion`), the secret key is regenerated deterministically from the decrypted seed, perfectly matching the public key previously registered on the server.

---

## 4. Credential Storage Architecture (Key Wrapping & Passkeys)

### Unlimited Accounts via Key Wrapping (Non-discoverable Credentials)
Standard WebAuthn credentials (default on sites like `webauthn.io`) use the **Key Wrapping** model:
1. During registration (`MakeCredential`), the key generates a random 32-byte `cred_seed`.
2. The structure `[alg (2B)] + [len (2B)] + [cred_seed (32B)] + [rp_id_hash (32B)]` is encrypted using **AES-256-CBC** and authenticated via **HMAC-SHA256**.
3. The encryption uses an on-chip **Master Key** derived from the RP2040 factory silicon unique identifier ([`pico_get_unique_board_id()`](file:///home/player999/Work/fido2/rp2040_fido2_pqc/src/storage.c#L23-L32)):
   $$\text{MasterKey} = \text{SHA-256}(\text{BoardUniqueID} \parallel \text{SALT})$$
4. The 144-byte ciphertext is returned to the browser as `credentialId` and stored in the Relying Party server database.
5. During authentication (`GetAssertion`), the server returns the `credentialId`. The RP2040 decrypts it, validates the HMAC, and verifies `rp_id_hash` (providing hardware-enforced anti-phishing protection).

*Key Advantages:*
* **Unlimited credential storage**: you can register on thousands of websites without filling device storage.
* **Device-bound security**: only your physical RP2040 chip can decrypt the credential.
* **No Flash wear**: zero EEPROM/Flash write cycles on account creation.

### Resident Keys (Discoverable Credentials / Passkeys)
For services supporting username-less login (Autofill Passkeys), [src/storage.c](file:///home/player999/Work/fido2/rp2040_fido2_pqc/src/storage.c) provides an in-memory resident credential table (`ResidentCredential`) capable of storing up to 8 discoverable credentials.

---

## 5. Hardware User Presence (UP)

To prevent unauthorized background access, every credential creation or signing request requires explicit human presence confirmation:

* **Safe BOOTSEL Polling from XIP Flash**: The `QSPI_CS` line is sampled by a dedicated RAM-resident routine ([`user_presence_is_button_pressed`](file:///home/player999/Work/fido2/rp2040_fido2_pqc/src/user_presence.c#L16-L30)). It temporarily disables interrupts, floats the CS line to High-Z, samples `sio_hw->gpio_hi_in`, and immediately restores standard XIP state.
* **500 Hz Polling Rate (2 ms Interval)**: Polling frequency is set to 2 ms, eliminating button debounce latency and capturing even ultra-brief taps (from 10 ms).
* **CTAPHID Keepalive**: Every 100 ms while waiting for touch, the authenticator dispatches `CTAPHID_CMD_KEEPALIVE` packets (`STATUS_UPNEEDED`). This informs the OS and browser that the token is actively waiting for human contact, preventing timeouts.
* **Compile-Time Isolation of Auto-Confirm**: Automated testing bypasses are completely compiled out via `#ifdef ENABLE_AUTO_CONFIRM`. Production builds enforce **strictly physical pushbutton touches**.

---

## 6. Hardware Status LED Indicator (WS2812 RGB)

The onboard WS2812 LED (GPIO 16) is driven by a dedicated state machine running on a hardware repeating timer interrupt at **33.3 Hz (30 ms)** via RP2040 PIO. Visual feedback remains fluid and responsive even during peak cryptographic CPU workloads.

| State | Color | Animation Pattern | Meaning to User |
|---|---|---|---|
| **IDLE** | 🔵 **Sapphire Blue** | Gentle calm breathing wave (`0, 0, 8..38`) | Device plugged in, ready and idle |
| **UP_REQUIRED** | 🟡 **Golden Yellow** | Rapid flashing at 4 Hz (`220, 180, 0`) | **User Presence Required!** Press the BOOTSEL button |
| **PQC_ACTIVE** | 🟣 **Neon Magenta / Violet** | Smooth breathing wave (`70..255, 0, 100..255`) | **Post-Quantum math in progress** (~2.2 s). Please wait |
| **SUCCESS** | 🟢 **Emerald Green** | Solid for 750 ms, gentle fade-out for 300 ms | Operation completed successfully |
| **ERROR** | 🔴 **Ruby Red** | Bright flash for 750 ms followed by fade-out | Request timeout or operation error |
| **BOOTLOADER**| 🟠 **Warm Amber** | Solid amber light (`255, 120, 0`) | Microcontroller rebooted to USB BOOTSEL mode |

> [!NOTE]
> The miniature WS2812 LED on Waveshare RP2040-One boards uses an **RGB** byte order (as opposed to typical GRB). The firmware explicitly compensates for this wiring.

---

## 7. BOOTSEL Programming Modes & Firmware Flashing

To facilitate rapid development and updates, the dongle can be returned to programming mode (USB Mass Storage `RPI-RP2`) **without unplugging it from the USB port**:

1. **One-Command Automatic Flashing**:
   ```bash
   bash scripts/flash.sh
   ```
   Automatically recompiles any code changes, triggers reboot, waits for the `RPI-RP2` drive to mount, copies `rp2040_fido2_pqc.uf2`, and returns to FIDO2 mode.
2. **Pushbutton Hold**:
   Press and hold the onboard **BOOT** button for longer than **2 seconds**. The LED will switch to amber, and the board reboots into BOOTSEL.
3. **USB CDC 1200 bps Touch**:
   ```bash
   stty -F /dev/ttyACM0 1200
   ```
4. **CDC Console Command**:
   Open a terminal on `/dev/ttyACM0` and press `b`.
5. **CTAPHID Vendor Reboot**:
   ```bash
   bash scripts/reboot_bootsel.sh
   ```

---

## 8. Building and Flashing

### Prerequisites:
* GNU Arm Embedded Toolchain (`arm-none-eabi-gcc` 10+ / 13+)
* Raspberry Pi Pico SDK (1.5.0+)
* CMake (3.13+) and GNU Make
* Open Quantum Safe library (`liboqs`)

### Build Steps:
```bash
# 1. Export environment variables
export PICO_SDK_PATH=/path/to/pico-sdk
export PATH=/path/to/toolchain/bin:$PATH

# 2. Create build directory
cd rp2040_fido2_pqc
mkdir -p build && cd build

# 3. Configure CMake with size and performance optimizations
cmake -DCMAKE_BUILD_TYPE=MinSizeRel ..

# 4. Compile
make -j$(nproc)
```
The build produces `build/rp2040_fido2_pqc.uf2`.

### Flashing:
Connect the Waveshare RP2040-One while holding the BOOT button (or simply run the flash script if the key is already running):
```bash
bash scripts/flash.sh
```

---

## 9. WebAuthn Compatibility & Verification

### Browser Testing on webauthn.io:
1. Open a WebAuthn-compliant browser (Google Chrome, Chromium, Firefox) and navigate to [https://webauthn.io/](https://webauthn.io/).
2. Enter a username.
3. Under **Algorithm**, choose:
   - **ML-DSA 87** (to test post-quantum FIPS 204);
   - or **ES512** / **ES256** (to test classical elliptic curves).
4. Click **Register**:
   - The dongle flashes golden yellow (waiting for User Presence).
   - Press the **BOOT** button on the dongle.
   - The LED begins breathing neon magenta (~2.2 s, keypair generation and attestation signature).
   - The LED flashes emerald green, and the browser displays: *"Success! Now try to authenticate..."*.
5. Click **Authenticate**:
   - The key flashes golden yellow — press the **BOOT** button.
   - After a brief magenta pulse, the key flashes green, and login completes successfully!

---

## 10. Project Directory Layout

```
rp2040_fido2_pqc/
├── CMakeLists.txt              # CMake configuration (Pico SDK, mbedtls, liboqs)
├── README.md                   # Technical documentation
├── include/
│   ├── ctap_constants.h        # CTAP 2.0 / 2.1 & COSE constants
│   ├── ctap_engine.h           # FIDO2 command dispatcher & parser
│   ├── crypto_engine.h         # Cryptographic interface (ML-DSA, ML-KEM, P-521, P-256)
│   ├── fido_cbor.h             # CBOR encoder & decoder routines
│   ├── fido_hid.h              # CTAPHID packet handling & keepalive definitions
│   ├── mbedtls_custom_config.h # Optimized mbedtls configuration
│   ├── status_led.h            # Status LED state machine header
│   ├── storage.h               # Key Wrapping & credential storage definitions
│   ├── tusb_config.h           # TinyUSB configuration (HID + CDC)
│   └── user_presence.h         # User Presence & BOOTSEL reboot declarations
├── scripts/
│   ├── flash.sh                # Automated build and flash script
│   ├── reboot_bootsel.sh       # CTAPHID vendor reboot utility
│   ├── test_ctap.py            # Low-level CTAPHID GetInfo diagnostic script
│   ├── test_fido2.py           # Cryptographic test suite
│   └── test_webauthn_site.py   # libfido2 browser-simulation test script
└── src/
    ├── crypto_engine.c         # liboqs & mbedtls cryptographic integration
    ├── ctap_engine.c           # MakeCredential, GetAssertion, GetInfo handlers
    ├── fido_cbor.c             # COSE key & CBOR response serialization
    ├── fido_hid.c              # USB HID transport layer & Keepalive transmitter
    ├── main.c                  # System setup, 200 MHz overclock, CDC console
    ├── status_led.c            # WS2812 PIO driver & hardware timer interrupt
    ├── storage.c               # AES-256 Master Key derivation & Key Wrapping
    ├── usb_descriptors.c       # FIDO2 CTAPHID & CDC USB descriptors
    ├── user_presence.c         # QSPI CS button sampler & debounce logic
    └── ws2812.pio              # PIO assembly timing program for WS2812
```

---

## License
This project is licensed under the MIT License. It incorporates components from the Raspberry Pi Pico SDK, TinyUSB, mbedTLS, and Open Quantum Safe (liboqs).
