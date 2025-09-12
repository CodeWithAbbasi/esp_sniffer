# Requirements for esp_sniffer

This project is developed using the **ESP-IDF framework**.  
To build and run the code, please make sure you have the following installed:

## 1. Hardware
- ESP32 development board (ESP32-WROOM-32 or compatible)
- USB cable for flashing

## 2. Software
- [ESP-IDF v4.4.3 or later](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/)
- Python 3.8+ (required by ESP-IDF tools)
- Git (to clone the repository and manage code)

## 3. Environment Setup
Install ESP-IDF and set up the environment variables:
```bash
git clone -b v4.4.3 https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh
. ./export.sh
idf.py --version

4. Build & Flash
From the root of this project:
idf.py set-target esp32
idf.py build
idf.py -p <YOUR_SERIAL_PORT> flash
idf.py monitor
