# WiFi Cracker v1

WiFi Cracker v1 is a Streamlit-based tool designed for educational and research purposes to assess WiFi security. The tool features dictionary-based, brute-force, and WPS PIN attacks for testing network strength against various security protocols.

> **Warning**: This software is intended only for use on networks you own or have explicit permission to test. Unauthorized use on others' networks is illegal and unethical.

## Table of Contents
- [Features](#features)
- [Setup](#setup)
- [Usage](#usage)
- [Requirements](#requirements)
- [Acknowledgments](#acknowledgments)

## Features
- **WPS PIN Attack**: Attempts common WPS pins, including manufacturer-specific patterns.
- **Dictionary Attack**: Uses a user-supplied dictionary to test for known passwords.
- **Brute Force Attack**: Generates combinations of passwords to crack networks with custom-defined length and character set.
- **MAC-based Manufacturer Detection**: Detects and displays the manufacturer of nearby networks based on MAC address (BSSID).

## Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Chungus1310/WifiCrackerv1.git
   cd WifiCrackerv1
   ```

2. **Install Requirements**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**
   ```bash
   streamlit run WiFiCrackerv1.py
   ```

## Usage

1. **Select Network Interface**: Choose your WiFi network interface from the dropdown.
2. **Scan Networks**: Click "Scan Networks" to discover nearby WiFi networks.
3. **Select Network**: Choose a network SSID to test and an associated BSSID (Access Point).
4. **Choose Attack Method**:
   - **Dictionary Attack**: Upload a `.txt` file containing possible passwords.
   - **Brute Force Attack**: Specify the character set and password length.
   - **WPS PIN Attack**: Uses WPS-specific pins based on manufacturer details.
5. **Monitor Results**: Progress and results display in real-time.

## Requirements
The following dependencies are necessary to run the tool:
- `streamlit==1.39.0`
- `pywifi==1.1.12`
- `comtypes==1.4.8`

### Notes
- This tool requires a compatible WiFi adapter.
- Ensure WiFi is enabled on your system and your adapter supports scanning and connection capabilities.

## Acknowledgments
This project leverages `pywifi` and `Streamlit` for network scanning and interactive interface creation. 
