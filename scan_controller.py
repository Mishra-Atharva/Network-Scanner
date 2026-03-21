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
from device_handler import Device_Manager
from network_scanner import NetworkScanner
from api_connector import *
import argparse

# Instantiate
dm = Device_Manager()
ns = NetworkScanner()

# Scanning for devices
def continuous_scan():

    while True:
        dm.add(ns.arp_scan())

# Checking device's status and then pushing them to the database
def status_update(auth: str):

    while True:
        time.sleep(120)

        dm.export_devices("devices.json")
        
        print("[*] Status Check Started!")
        dm.add(ns.check_devices(dm.devices))
        print("[*] Status Update Complete!")

        dm.export_devices("devices.json")

        for dev in dm.devices:
            push_to_database(dev.export(), auth)
        print("[*] Database Updated!")

# Main function
def main(args):
    
    dm.import_devices("devices.json")
    for dev in dm.devices:
        print(dev.export())

    if args.command == "login":
        auth = login(args.email, args.password)
        if auth is None:
            print("[!] Failed to login!")
            exit()

    elif args.command == "register":
        auth = signup(args.email, args.password, args.fname, args.lname) 
        if auth is None:
            print("[!] Failed to create account!")
            exit()
        else: 
            print("[*] Account Created Successfully!")

    print("[*] Login was Successfully!")

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
    parser = argparse.ArgumentParser()
    sub_parser = parser.add_subparsers(dest="command")

    login_parser = sub_parser.add_parser("login")
    login_parser.add_argument("-u", dest="email", required=True, help="Email")
    login_parser.add_argument("-p", dest="password", required=True, help="Password")

    register_parser = sub_parser.add_parser("register")
    register_parser.add_argument("-f", dest="fname", required=True, help="First Name")
    register_parser.add_argument("-l", dest="lname", required=True, help="Last Name")
    register_parser.add_argument("-u", dest="email", required=True, help="Email")
    register_parser.add_argument("-p", dest="password", required=True, help="Password")


    args = parser.parse_args()

    main(args)

