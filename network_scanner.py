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

import netifaces
import ipaddress
import nmap
import requests
import logging as log 
import socket
from scapy.all import *
from yaspin import yaspin
from device_handler import Device
from pythonping import ping 
from device_handler import Device

# Loggins Setup 
log.basicConfig(level= log.DEBUG, format="[ %(levelname)s ]  %(message)s | [ %(function)s ] | [ %(asctime)s ]", datefmt="%Y-%m-%d %H:%M:%S", filename="NetworkScannerLogs.log")


MASK = "255.255.255.0"

# Network Scanner class contains ARP scan and MDNS scan function
# After initializing the NetworkScanner object, use the arp_scan() to scan the network for the devices
# Both scans will return a list of devices, which then need to cleaned later to avoid duplicate devices
class NetworkScanner:

    # Setup
    def __init__(self):

        router_ip = netifaces.gateways().get('default', {}).get(netifaces.AF_INET)[0]
        self.subnet = str(ipaddress.IPv4Interface(f"{router_ip}/{MASK}").network)
        self.nm = nmap.PortScanner()

    def check_devices(self, devices: list[Device]) -> list[Device]:

        for d in devices:
            response = ping(target=d.get_ip(), count=1, verbose=False)
            if (response.packet_loss > 0):
                d.set_status("Offline")
            else:
                d.set_status("Online")

            with yaspin(text="[ Port Scanning ] - Check for open ports") as sp:
                d.set_ports(self.port_scanner(d.get_ip()))
            sp.ok()

        print("[*] Device Check Completed!")
        return devices

    def port_scanner(self, ip: str):
    
        # For storing open ports
        ports = []

        # Scanning the device for open ports
        self.nm.scan(ip, arguments="-F")
    
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():

                # Grabbing all ports
                lport = self.nm[host][proto].keys()
        
                # Finding open ports
                for port in lport:
                    if (self.nm[host][proto][port]['state'] == "open"):
                        ports.append(port)

        if len(ports) > 0:
            print("[*] Found open ports")
        else:
            print("[*] No open ports found")

        # Return all open ports found
        return ports

    # REVERSE DNS --> Getting name of devices
    def reverse_dns(self, ip: str, mac: str) -> str:
        try:
            name = socket.gethostbyaddr(ip)[0]
            return name 
        
        except:
            url = f"https://api.maclookup.app/v2/macs/{mac.replace(":", "")[:6]}"
            resp = requests.get(url)

            if resp.status_code < 400:
                return resp.json()['company']

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
                name = self.reverse_dns(recv.psrc, recv.hwsrc)
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
