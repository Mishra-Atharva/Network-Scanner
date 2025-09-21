from zeroconf import Zeroconf, ServiceBrowser, ServiceListener
from scapy.all import ARP, Ether, srp
from yaspin import yaspin
import tabulate
import socket
import time 
import argparse

# UPnP/SSDP
MCAST_GRP = "239.255.255.250"
MCAST_PORT = 1900

class Devices:

    def __init__(self, name: str = None, ip: str = None, mac: str = None, port: str = None, service: str = None):

        self.name = name 
        self.ip_addr = ip 
        self.mac_addr = mac 
        self.port = port 
        self.service_type = service 
    
    def to_string(self):
        print(f"Name: {self.name}\nIP Address: {self.ip_addr}\nMac Address: {self.mac_addr}\nPort: {self.port}\nService Type: {self.service_type}")
       

class DeviceListener(ServiceListener):

    SERVICES = [
         "_googlecast._tcp.local.",         # Google Home, Nest, Chromecast
        "_hap._tcp.local.",                 # Apple HomeKit Accessories
        "_homekit._tcp.local.",             # Apple HomeKit (alternative)
        # "_airplay._tcp.local.",           # Apple AirPlay (DOESN'T WORK)
        # "_companion-link._tcp.local.",    # Apple Companion Link (DOESN'T WORK)
        "_sonos._tcp.local.",               # Sonos Speakers
        # "_spotify-connect._tcp.local.",     # Spotify Connect
        "_philips-hue._tcp.local.",         # Philips Hue Bridge
        "_roku._tcp.local.",                # Roku devices
        "_bose._tcp.local.",                # Bose SoundTouch
        "_amzn-wplay._tcp.local.",          # Amazon Whisperplay (Fire TV)
        "_tplink._tcp.local.",              # TP-Link Kasa devices? (Less common)
        "_http._tcp.local.",                # Any device with a web server
        "_printer._tcp.local.",             # Network Printers
        "_ssh._tcp.local.",               # Devices with SSH (Raspberry Pi, etc.) (DOESN'T WORK)
        "_workstation._tcp.local.",         # PCs and Macs
    ]

    def __init__(self):
        self.devices = []
    
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:

        info = zc.get_service_info(type_, name)

        if (info):

            try:
                name = info.properties[b'md'].decode('utf-8', errors='ignore')

            except KeyError:

                try:
                    name = info.properties[b'n'].decode('utf-8', errors='ignore')
                
                except KeyError:
                    name = info.server

            if (info.addresses):
                ip = socket.inet_ntoa(info.addresses[0])
            else:
                ip = "Unknown-IP"
            
            try:
                port = info.port 

            except:
                port = "Uknown-PORT"

            device = Devices(name , ip, None, port, 'mDNS')

            self.devices.append(device)

# UPnP / SSDP --> Multicast devices
def scan_upnp_ssdp(timeout: int, exclude_ips: list = None):

    # Message
    ssdp_request = (
        'M-SEARCH * HTTP/1.1\r\n'
        f'HOST: {MCAST_GRP}:{MCAST_PORT}\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 2\r\n'
        'ST: ssdp:all\r\n'
        '\r\n'
    )

    if exclude_ips is None:
        exclude_ips = []
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)

    sock.sendto(ssdp_request.encode('utf-8'), (MCAST_GRP, MCAST_PORT))
    
    with yaspin(text="[ UPnp/SSDP ] - Scanning for devices...") as sp:

        seen = set()
        try:
            while True:
                data, addr = sock.recvfrom(65507)
                ip = addr[0]

                if ip in exclude_ips:
                    continue 

                if ip not in seen:
                    print(f"\n[+] Device at {ip}:\n{data.decode(errors='ignore')}")
                    seen.add(ip)
        except:
            sp.ok

        finally:
            sp.ok
            sock.close()


# mDNS --> IoT Devices
def scan_mDNS(duration) -> list:

    with yaspin(text = "[ mDNS ] - Scanning for devices...") as pbar:

        listener = DeviceListener()
        zc = Zeroconf()

        browser = [ServiceBrowser(zc, service, listener) for service in DeviceListener.SERVICES]

        scan_duration = duration

        for _ in range(scan_duration):
            time.sleep(1)
        pbar.ok
   
    zc.close()
    
    return listener.devices

# REVERSE DNS --> Getting name of devices
def reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name 
    
    except:
        return None

# ARP SCAN --> All connected devices on the network
def scan_network(subnet: str = "192.168.1.0/24", timeout: int = 5) -> list:

    with yaspin(text="[ ARP ] - Scanning the network...") as sp:
        
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        data = srp(packet, timeout=timeout, verbose=False)[0]

        devices = []

        for sent, recv in data:

            # Details
            name = reverse_dns(recv.psrc)
            ip = recv.psrc
            mac = recv.hwsrc

            # Creating device object
            device = Devices(name, ip, mac, None, 'ARP')

            # Adding to the list of devices discovered
            devices.append(device)

        sp.ok
    
    return devices

# Clears up duplicate devices
def clean_devices(list_a, list_b) -> dict:

    devices = {}
    counter = 0
    same_device = False

    if (len(list_a) == 0 and len(list_b) == 0):
        return None   

    elif (len(list_a) > 0 and len(list_b) == 0):
        return list_a 

    elif (len(list_a) == 0 and len(list_b) > 0):
        return list_b 

    else:

        for a in list_a:
            for b in list_b:
                if (a.ip_addr == b.ip_addr and not(same_device)):

                    same_device = True
                    
                    # Managing Device Details
                    if (a.name is None and b.name is not None):
                        name = b.name
                    elif (b.name is None and a.name is not None):
                        name = a.name 
                    elif (a.name is not(None) and b.name is not None):
                        name = f"{b.name}/{a.name}"
                    else:
                        name = "Uknown-Device"
                    
                    ip = a.ip_addr
                    mac = a.mac_addr
                    port = b.port
                    service_type = f"{a.service_type}/{b.service_type}"

                    device = {
                        'name': name,
                        'ip': ip,
                        'mac': mac,
                        'port': port,
                        'type': service_type
                    }

                    devices[counter] = device 
                    counter += 1
                    break 
            
            if (not(same_device)):

                device = {
                    'name': "Unknown-Device" if a.name is None else a.name,
                    'ip': a.ip_addr,
                    'mac': a.mac_addr,
                    'port': a.port,
                    'type': a.service_type
                }

                devices[counter] = device
                counter += 1

            else:
                same_device = False

        same_device = False

        for b in list_b:
            for dev in devices:

                if (devices[dev]['ip'] == b.ip_addr):
                    same_device = True 

            if (not(same_device)):

                device = {
                    'name': b.name,
                    'ip': b.ip_addr,
                    'mac': b.mac_addr,
                    'port': b.port,
                    'type': b.service_type
                }

                devices[counter] = device
                counter += 1

            else:
                same_device = False

    # Combined list of a, b
    return devices

# Creating a table for clean display of devices found
def show_table(devices) -> None:

    if (devices is None):
        print("[*] No devices were found!")
        return 
    
    table_data = []
    headers = ['Name', 'IP Address', 'MAC Address', 'Port', 'Service Type']

    for device in devices:

        table_data.append([
            devices[device]['name'],
            devices[device]['ip'],
            devices[device]['mac'],
            devices[device]['port'],
            devices[device]['type']
        ])
    
    output_table = tabulate.tabulate(tabular_data=table_data, headers=headers, tablefmt='pretty')
    print(output_table)

def find_subnet():
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
        print(f"[!] {e}")
        return None

# Main function
def main(args):

    if (args.find):

        try:
            subnet = find_subnet()

            if (subnet is None):
                raise Exception("Couldn't get subnet.")

            arp_devices = scan_network(subnet, args.timeout)
            if (len(arp_devices) == 0):
                print("[ ARP ] Couldn't find any devices!")

        except:
            arp_devices = scan_network(args.subnet, args.timeout)
            if (len(arp_devices) == 0):
                print("[ ARP ] Couldn't find any devices!")
        
    else:
        print(f"[*] Subnet set to: {args.subnet}")
        arp_devices = scan_network(args.subnet, args.timeout)
        if (len(arp_devices) == 0):
            print("[ ARP ] Couldn't find any devices!")

    mdns_devices = scan_mDNS(args.duration)
    if (len(mdns_devices) == 0):
        print("[ mDNS ] Couldn't find any devices!")

    upnp_ssdp_devices = scan_upnp_ssdp(args.timeout, exclude_ips=[args.exclude])
    # if (len(upnp_ssdp_devices) == 0):
    #     print("[ UPnP/SSDP ] Couldn't find any devices!")

    devices = clean_devices(arp_devices, mdns_devices)
    show_table(devices)

if __name__ == '__main__':

    parser = argparse.ArgumentParser("Network Scanning")
    parser.add_argument("--find", action='store_true', default=False, help="Find subnet automatically")
    parser.add_argument("--subnet", type=str, default="192.168.1.0/24", help="Enter subnet eg. 192.168.1.0/24")
    parser.add_argument("--duration", type=int, default=20, help="How long of a scan do you want for mDNS?")
    parser.add_argument("--timeout", type=int, default=5, help="How long of a scan do you want for ARP?")
    parser.add_argument("--exclude", type=str, default="192.168.1.1", help="Exclude router ip")
    parser.add_argument("--export", action='store_true', default=False, help="Export discovered devices to .json file")
    args, unknown = parser.parse_known_args()
    main(args)