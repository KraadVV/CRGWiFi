# Decrypt AES-CCMP

from Crypto.Cipher import AES
from scapy.all import *
import struct
import binascii

class WPA2DecryptionBox:
    def __init__(self, pkt, tk_key):
        self.pkt = pkt
        self.tk_key = tk_key
        self.TA = binascii.a2b_hex(self.pkt.getlayer(Dot11).addr2.replace(':',''))
        self.PN = self.make_PN()

    def make_PN(self):
        CCMP_header = bytes(self.pkt.getlayer(Dot11CCMP))        
        PN = (CCMP_header[0:2] + CCMP_header[4:8])[::-1]
        #print(b'debug : ' + PN)
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
        ciphertext = ciphertext [:-8] # exclude MIC
        ciphertext += b'\x00' * (len(ciphertext) % 16)
        block_len = len(ciphertext) // 16

        cipher = AES.new(self.tk_key, AES.MODE_ECB)        
        for idx in range(block_len):
            xordata = cipher.encrypt(self.make_CTR_PRELOAD(idx))
            for i,j in zip(xordata, ciphertext[16*idx : 16*(idx+1)]):
                plaintext += bytes([i^j])

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

def decrypt(self, location):
#if __name__== '__main__':
    sample = PcapReader("/home/hunjison/Desktop/CRGWiFi/wpa-Induction.pcap")
    pkt_list = sample.read_all()
    tk_key = b'\x00'*16

    idx = 0
    for idx in range(len(pkt_list)):
        pkt = pkt_list[idx]
        if pkt.getlayer(Dot11CCMP):
            if pkt.getlayer(Dot11).type == 2:
                #print("pkt select done! : number = ", idx)
                wpa2decryptionbox = WPA2DecryptionBox(pkt, tk_key)
                
                break
    
    wpa2decryptionbox.save_packet()
    print('done!')

