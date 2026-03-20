"""
Program: Scan Controller
Description: Use the NetowrkScanner and DeviceHandler in order to scan the network for devices
Author: Atharva Mishra

Libraries Used:
    [-] Threading - 
    [-] Time -     
    [-] Device Manager - List of Devices
    [-] NetworkScanner - Arp Scan
    [-] Status - Pinging Devices from the list of devices
"""

import threading
import time
from router_manager import Router
from device_handler import Device_Manager
from network_scanner import NetworkScanner
from status_handler import Status
from api_connector import push_to_database, login


dm = Device_Manager()
ns = NetworkScanner()
st = Status()


def continuous_scan():

    while True:
        dm.add(ns.arp_scan())


def status_update(auth: str):

    while True:
        time.sleep(120)
        dm.add(st.check_devices(dm.devices))
        dm.export_devices("devices.json")

        for dev in dm.devices:
            push_to_database(dev.export(), auth)
    

def main():
    
    # Router("username", "password")
    dm.import_devices("devices.json")

    auth = login()
    
    _continuous = threading.Thread(target=continuous_scan, daemon=True)
    _status = threading.Thread(target=status_update, daemon=True, args=(auth,))

    _continuous.start()
    _status.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Shutting down...")


if __name__ == "__main__":
    main()