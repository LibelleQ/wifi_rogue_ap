from scapy.all import *

import argparse
import subprocess
import sys
import time
import os

DEAULT_CHANNEL = 6
CAPTURE_FILE = "capture.pcap"
DNSMASQ_CONF = "/tmp/dnsmasq.conf"
HOSTAPD_CONF = "/tmp/hostapd.conf"
HTML_PAGE =  "./index.html"

""" 
class WfiRguAP:
    def monitor_mode(self, interface):
        print(f"[+] Activation Monitor mode on {interface}")
        try:
            subprocess.run(['airmon-ng', 'check', 'kill'], check=True)
            subprocess.run(['airmon-ng', 'start', interface], check=True)
            return f"{interface}mon"
        except subprocess.CalledProcessErrora as e:
            print(f"[-] Error during configuration of monitor mode")
            sys.exit(1)

 """



""" def interface(target_ssid, target_MAC):
    iface = "wlan0mon"
    sender_mac =  RandMAC()
    ssid = target_ssid
    dot11 = Dot11(type=0,subtype=8, addr1=target_MAC, addr2= sender_mac, addr3=sender_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame= RadioTap()/dot11/essid
    sendp(frame, inter=0.1,iface=iface, loop=1) """

"""  parser = argparse.ArgumentParser(
    prog=' Wfi Rgue AP',
    description='Rogue AP Attack')

    parser.add_argument('-t', '--target', required=True, help='Name Target')
    parser.add_argument('-s', '--ssid', required=True, help='SSID target')
    parser.add_argument('-m', '--monitor', required=True, help='Monitor mode')
    parser.add_argument('-c', '--channel', type=int, default=DEAULT_CHANNEL)

    args = parser.parse_args() """


def init_apache2(self):
    print(f"[+] Launching Appache Server & HTML Page")
    try:
        subprocess.run(['python3', '-m', 'http.server', '--bind', '127.0.0.1', '9000'],check=True)
        subprocess.run(['echo', HTML_PAGE , '>', '~/index.html' ], check=True)
        return f"Success creating HTML Page"
    except subprocess.CalledProcessError as e:
        print(f"[-] Error during server creation")
        sys.exit(1)

def start(self):
    print(f"[+] Launching Attack")
    init_apache2()




start()