"""
Program: Device Handler
Description: Script to hold classes for handling devices
Author: Atharva Mishra

Libaries Used:

    [-] Json - Used for reading json files
    [-] PathLib - Used to check if the file exists
    [-] Logging - For logging issues
"""

import json
from pathlib import *
import logging as log
from pprint import pprint

# Loggins Setup 
log.basicConfig(level= log.DEBUG, format="[ %(levelname)s ]  %(message)s | [ %(function)s ] | [ %(asctime)s ]", datefmt="%Y-%m-%d %H:%M:%S", filename="NetworkScannerLogs.log")


# Device Class holds the template for how the information for the device will be stored.
# The device class won't hold any device information and instead return a dictionary containg the device info to the Device Manager.

"""
    {
        name: "device_name",
        ip_addr: "device_ip",
        mac_addr: "device_mac",
        ports: [],
        status: "Online" | "Offline"
    }
"""

# Details for devices
# 1 file will focus on getting the devices, their name, ip, and mac address
# 1 file will focus on getting a list of all the open ports of the devices 

class Device:

    # Setup
    def __init__(self, name: str, ip: str, mac: str, ports: list = [], status: str = "Offline"):

        self.d_name = name
        self.d_ip = ip
        self.d_mac = mac
        self.d_ports = ports
        self.d_status = status
    
    # Returns an dictionary contain information about the device
    def export(self):
        
        return {
            "name": self.d_name,
            "ip": self.d_ip,
            "mac": self.d_mac,
            "ports": self.d_ports,
            "status": self.d_status
        }

    # Setters
    def set_name(self, new_value): self.d_name = new_value
    def set_ip(self, new_value): self.d_ip = new_value
    def set_mac(self, new_value): self.d_mac = new_value
    def set_ports(self, new_value): self.d_ports = new_value
    def set_status(self, new_value): self.d_status = new_value

    # Getters
    def get_name(self): return self.d_name
    def get_ip(self): return self.d_ip
    def get_mac(self): return self.d_mac
    def get_ports(self): return self.d_ports
    def get_status(self): return self.d_status
        
# Device Manager stores all the devices in an array. 

"""
Device Manager Class Structure
[
    {
        name: "device_name",
        ip_addr: "device_ip",
        mac_addr: "device_mac",
        open_ports: [],
        status: "Online" | "Offline"
    },
    {
        name: "device_name",
        ip_addr: "device_ip",
        mac_addr: "device_mac",
        open_ports: [],
        status: "Online" | "Offline"
    }
]
"""

# Inside the array there are multiple devices stored in a dictionary
# The Device Manager will temporarily hold the list of devices until the program end

class Device_Manager:

    # Setup
    def __init__(self):
       self.devices = []


    # Adds new devices to the list of devices
    def add(self, devices: list[Device]) -> None:

        self.devices.extend(devices)
        self.devices = self.clean_list(self.devices)
        # pprint([d.export() for d in self.devices])


    # Removes all duplicate devices from the list
    def clean_list(self, devices: list[Device]) -> list[Device]:
        
        seen_ips = set()
        unique_new_devices = []
        for device in devices:
            if device.get_ip() not in seen_ips:
                unique_new_devices.append(device)
                seen_ips.add(device.get_ip())
        
        return unique_new_devices
    

    # Import devices from an json file
    def import_devices(self, file: str) -> bool:
        
        # Check file
        file_path = Path(file)

        if (file_path.exists() and not(file_path.is_dir())):

            # Read file
            with file_path.open("r") as fp:

                # Parse file
                data = json.load(fp) 

                # Extracting 
                for device in data:

                    # add to the deivces list
                    self.devices.append(Device(*device.values()))

                # Close file
                fp.close()

            # Success
            return True

        else:

            log.error("File doesn't exist", extra={"function": "Device_Manager.import_devices"})

            # Failure
            return False
    

    # Exports all devices into a json file
    def export_devices(self, file: str) -> None:

        # Check file
        file_path = Path(file)

        # Write to file
        with file_path.open("w") as fp:

            # Converts all the objects in the self.devices array into json format
            devices = [d.export() for d in self.devices]

            json.dump(devices, fp, indent=4)

            # Close file
            fp.close()



# Testing Classes and Functions
if __name__ == "__main__":

    dev_1 = Device("device_name", "device_ip", "device_mac", [0], "Online")
    dev_2 = Device("device_name", "device_ip", "device_mac", [12], "Online")
    dev_3 = Device("device_name", "device_ip2", "device_mac", [0], "Online")
    dev_4 = Device("device_name", "device_ips", "device_mac", [12], "Online")

    dm = Device_Manager()
    dm.add([dev_1, dev_2])
    dm.add([dev_3, dev_4, dev_1])
    dm.export_devices("device.json")
