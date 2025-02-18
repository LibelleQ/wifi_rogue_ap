from scapy.all import *

import subprocess
import sys

DEAULT_CHANNEL = 6
HTML_PAGE =  "./index.html"
INTERFACE = "wlan0"
TARGET = "" 
TARGET_FILE = "target_file.txt"

class WfiRguAP:
    def monitor_mode(self):
        print(f"[+] We need interface to target : ")
        input(INTERFACE)
        if INTERFACE == "": 
            INTERFACE = "wlan0"
        print(f"[+] Activation Monitor mode on {INTERFACE}")
        try:
            subprocess.run(['airmon-ng', 'check', 'kill'], check=True)
            subprocess.run(['airmon-ng', 'start', INTERFACE], check=True)
            return f"{INTERFACE}"
        except subprocess.CalledProcessErrora as e:
            print(f"[-] Error during configuration of monitor mode")
            sys.exit(1)

    def scanning(self):
        print(f"[+] Scanning network to find WPA Enterprise")
        try:
            subprocess.run(['airodumb-ng', '--encrypt', 'WPA2', INTERFACE, '>', TARGET_FILE])
            stop_scanning = input()
            if stop_scanning == "stop":
                return f"Test"
        except subprocess.CalledProcessError as e :
            print(f"[-] Error during network scanning")
            sys.exit(1)

    def choice_target(self):
        subprocess.run(['cat', TARGET_FILE])
        print(f"[+] Select target Network >")
        input(TARGET)


def init_apache2():
    print("[+] Launching Apache Server & HTML Page")
    try:
        subprocess.run(['python3', '-m', 'http.server', '--bind', '127.0.0.1', '9000'], check=True)
        subprocess.run(['cp', HTML_PAGE, '~/index.html'], check=True)
        print("Success creating HTML Page")
    except subprocess.CalledProcessError:
        print("[-] Error during server creation")
        sys.exit(1)

def start():
    print("[+] Launching Attack")
    init_apache2()


if __name__ == "__main__":
    input(INTERFACE)
    rogueAP = WfiRguAP
    rogueAP.monitor_mode()
    rogueAP.scanning()
    rogueAP.choice_target()
    start()