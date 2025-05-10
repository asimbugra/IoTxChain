# IoTxChain

**IoTxChain** is a lightweight C++ blockchain transaction library designed for microcontrollers, specifically ESP32, to interact directly with the **Solana blockchain** and **Anchor framework** smart contracts.

---

## ✨ Features

- 🪙 Send SOL or SPL token transactions from ESP32
- 🧠 Build and sign Anchor-compatible instructions
- 🔒 Ed25519 signing using pure C/C++ (no external tools)
- 📡 Full compatibility with Solana JSON RPC
- 🧩 Includes utilities like base58 decoding and memo program

---

## 📦 Folder Structure

IoTxChain/
├── src/
│   ├── IoTxChain-lib.h / .cpp
│   ├── base58.h / .cpp
│   └── …
├── lib/
│   ├── ArduinoJson/
│   ├── Crypto/
│   └── micro-ecc/
├── examples/
│   └── BasicTransfer/
├── library.json
└── README.md
---

## ⚙️ PlatformIO Setup

Add the following to your `platformio.ini` file:

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino

lib_deps =
    asimbugra/IoTxChain@1.0.3
    ArduinoJson@^6.21.5
    https://github.com/rweather/arduinolibs.git
    https://github.com/kmackay/micro-ecc.git

lib_extra_dirs = lib

build_flags =
  -UCONFIG_BT_ENABLED
  -UCONFIG_BLUEDROID_ENABLED
  -DCONFIG_BT_ENABLED=0
  -DCONFIG_BLUEDROID_ENABLED=0
  -DCONFIG_HEAP_POISONING_COMPREHENSIVE
  -DARDUINO_ARCH_ESP32
  -DED25519_TEST
  -DED25519_NO_SEED
  -std=gnu++17
  -w

monitor_speed = 115200