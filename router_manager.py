"""
Program: Router Manager
Description: Setups details about the router for easier and faster control
Author: Atharva Mishra
"""
import json
import requests
from test import RouterApiFinder

class Router:

    def __init__(self, ip: str = None, username: str = None, password: str = None):
        self.devices = []
        self.router_ip = ip
        self.user = username
        self.pwd = password 
        self.raf = RouterApiFinder(self.router_ip, self.user, self.pwd)
        self.model = None 
        self.api_url = None 

    def ready_router(self):
        self.model = self.raf.detect_router_type()
        self.api_url = self.raf.scan()

    def get_devices(self): 
        return self.devices

    def get_model(self):
        return self.model

    def set_password(self, new_pwd):
        self.pwd = new_pwd 

    def set_username(self, new_user):
        self.user = new_user 

    def call_devices(self):
        url = self.api_url[0]['url']
        print(self.api_url[0]['url'])
        s = requests.Session()
        s.auth = (self.user, self.pwd)
        s.timeout = 10 
        s.headers.update({
            "User-Agent": "RouterApiFinder/1.0"
        })

        resp =  s.request("GET", url, timeout = 10, )
        if resp.status_code < 400:
            with open("dev_list.json", "w") as f: 
                json.dump(resp.json(), f, indent=4)

            return resp.json()

if __name__ == "__main__":
    router = Router("192.168.1.1", "admin", "Atmimiva16205!")
    router.ready_router()
    router.call_devices()
