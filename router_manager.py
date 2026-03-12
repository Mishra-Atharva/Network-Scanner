"""
Program: Router Manager
Description: Setups details about the router for easier and faster control
Author: Atharva Mishra
"""
import logging
import requests
import netifaces
import ipaddress
from api_scanner import RouterApiFinder
from device_handler import Device, Device_Manager

logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

MASK = "255.255.255.0"

class Router:

    # Setting up the router auth
    def __init__(self, username: str = None, password: str = None):

        self.dev_manager = Device_Manager()

        self.router_ip = netifaces.gateways().get('default', {}).get(netifaces.AF_INET)[0]
        self.subnet = str(ipaddress.IPv4Interface(f"{self.router_ip}/{MASK}").network)

        self.user = username
        self.pwd = password 

        self.raf = RouterApiFinder(self.router_ip, self.user, self.pwd, timeout=10)

        self.model = self.raf.detect_router_type()
        self.api_url = self.raf.scan()

        self.call_devices()

    # Getting the list of devices from the api url
    def call_devices(self):

        url = self.api_url[0]['url']

        s = requests.Session()
        s.auth = (self.user, self.pwd)
        s.verify = False
        s.timeout = 10 
        s.headers.update({
            "User-Agent": "RouterApiFinder/1.0"
        })

        resp =  s.request("GET", url, timeout = 10, )
        if resp.status_code < 400:
                self.clean_devices(resp.json())
    
    # Extracts the neccesssary information from the list of devices pulled from the api url
    def clean_devices(self, data):

        devices = []

        for dev in data:
            devices.append(Device(data[dev]["__name"], data[dev]["__ip"], data[dev]["__mac"]))

        self.dev_manager.add(devices)
        self.dev_manager.export_devices("devices.json")

if __name__ == "__main__":
    pass