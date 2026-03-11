"""
Program: Status Handler
Description: Once the devices.json file has devices in it, each device will be pinged every 5 minutes in order to update the status of the device.
Author: Atharva Mishra

Libraries Used:
    [-] Device Handler
    [-] Device
"""

from pythonping import ping 
from device_handler import Device

class Status:
    
    def check_devices(self, devices: list[Device]) -> list[Device]:

        for d in devices:
            response = ping(target=d.get_ip(), count=1, verbose=False)
            if (response.packet_loss > 0):
                d.set_status("Offline")
            else:
                d.set_status("Online")

        print("Status Updated")
        return devices


if __name__ == "__main__":

    result = ping(target="192.168.1.103", count=1, verbose=True)
    if (result.packet_loss > 0):
        print("offline")
    else:
        print("online")