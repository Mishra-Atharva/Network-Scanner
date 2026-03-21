import requests
import logging
logging.getLogger("urllib3").setLevel(logging.WARNING)

def login(email: str, password: str):

    data = {
        "email": email,
        "password": password 
    }

    try: 
        login = requests.post("http://localhost:8080/api/user/authenticate", json=data)
        return login.json()["token"]

    except requests.exceptions.ConnectionError:
        print("[!] Server is down!")
    except Exception as e: 
        print(f"[!] Error: {e}")


def signup(email: str, password: str, first_name: str, last_name: str):
    data = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": password 
    }

    try: 
        signin = requests.post("http://localhost:8080/api/user/register", json=data)
        return signin.json()["token"]

    except requests.exceptions.ConnectionError:
        print("[!] Server is down!")
    except Exception as e: 
        print(f"[!] Error: {e}")


def push_to_database(data: dict, auth: str):

    res = requests.post("http://localhost:8080/api/device/register", json=data, headers={"Authorization": f"Bearer {auth}"} )
    print(res.json())

