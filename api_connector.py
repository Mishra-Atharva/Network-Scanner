import requests

def login():

    data = {
        "email": "atharvamishra3@gmail.com",
        "password": "hellothere!"
    }
    login = requests.post("http://localhost:8080/api/user/authenticate", json=data)
    return login.json()["token"]

def push_to_database(data: dict, auth: str):

    res = requests.post("http://localhost:8080/api/device/register", json=data, headers={"Authorization": f"Bearer {auth}"} )
    print(res.json())


if __name__ == "__main__":
    login()