"""
Program: Network Scan Handler
Description: Scan the network for devices by sending ARP packets
Author: Atharva Mishra

Libraries Used:
    [-] Scapy - For sending ARP request to get devices on the network
    [-] Socket - For getting device names
    [-] Yaspin - For loading status
    [-] DeviceHandler - For Device 
    [-] Logging - For logging issues
"""

import logging as log 
import socket
from scapy.all import *
from yaspin import yaspin
from device_handler import Device
# from zeroconf import Zeroconf, ServiceBrowser, ServiceListener


# Loggins Setup 
log.basicConfig(level= log.DEBUG, format="[ %(levelname)s ]  %(message)s | [ %(function)s ] | [ %(asctime)s ]", datefmt="%Y-%m-%d %H:%M:%S", filename="NetworkScannerLogs.log")


# Network Scanner class contains ARP scan and MDNS scan function
# After initializing the NetworkScanner object, use the arp_scan() and/or mdns_scan() to scan the network for the devices
# Both scans will return a list of devices, which then need to cleaned later to avoid duplicate devices
class NetworkScanner:

    # Setup
    def __init__(self):
        self.subnet = self.find_subnet()

    def find_subnet(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            sock.close()

            counter = 0
            length = 0

            for i in range(len(ip)-1):
                if (ip[i] == '.'):
                    counter += 1
                
                if (counter == 3):
                    length = i 
                    break 
            
            subnet = f"{ip[:length]}.0/24"
            print(f"[*] Subnet set to: {subnet}")
            return subnet
            
        except Exception as e:
            log.error(e, extra={"function": "NetworkScanner.find_subnet"})
            return None

    # REVERSE DNS --> Getting name of devices
    def reverse_dns(self, ip: str) -> str:
        try:
            name = socket.gethostbyaddr(ip)[0]
            return name 
        
        except:
            return None

    # ARP SCAN --> All connected devices on the network
    def arp_scan(self, timeout: int = 60) -> list:

        with yaspin(text="[ ARP ] - Scanning the network...") as sp:
            
            arp = ARP(pdst=self.subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            data = srp(packet, timeout=timeout, verbose=False)[0]

            devices = []

            for sent, recv in data:

                # Details
                name = self.reverse_dns(recv.psrc)
                ip = recv.psrc
                mac = recv.hwsrc

                # Creating device object
                device = Device(name, ip, mac, None, "Online")

                # Adding to the list of devices discovered
                devices.append(device)

            sp.ok
        
        return devices


if __name__ == "__main__":

    ns = NetworkScanner()
    devices = ns.arp_scan()

    for d in devices:
        print(d.export())
