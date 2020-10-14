from scapy.all import *
from hashlib import pbkdf2_hmac, sha1, md5
from Crypto.Cipher import AES
import binascii
import hmac

class GetPTK():
    def __init__(self, ssid, pw, aNonce, sNonce, APmac, STAmac):
        self.ssid = ssid
        self.pw = pw
        self.aNonce = aNonce
        self.sNonce = sNonce
        self.APmac = APmac
        self.STAmac = STAmac
        self.setting()

    def setting(self):
        A, B = self.makeAB()
        pmk = self.makePMK()
        ptk = self.PRF(pmk, A, B)
        tk_key = self.make_tk_key(ptk) # key for WPA2 AES Decryption
        self.tk_key = tk_key

    def makeAB(self):
        A = b"Pairwise key expansion"
        B = min(self.APmac, self.STAmac) + max(self.APmac, self.STAmac) + min(self.aNonce, self.sNonce) + max(self.aNonce, self.sNonce)
        return (A, B)

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

    def makePMK(self):
        pmk = pbkdf2_hmac('sha1', self.pw.encode('ascii'), self.ssid.encode('ascii'), 4096, 32)
        return pmk

    def make_tk_key(self, ptk):
        return ptk[32:48]


class WPA2DecryptionBox:
    def __init__(self, pkt, tk_key):
        self.pkt = pkt
        self.tk_key = tk_key
        self.count = 0

    def check_CCMP(self): # In Some case, Group Cipher suite is TKIP..
        return bool(self.pkt.getlayer(Dot11CCMP))

    def setting(self):      
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
        ciphertext = ciphertext[8:]  # exclude MIC
        ciphertext += b'\x00' * (len(ciphertext) % 16)
        block_len = len(ciphertext) // 16

        cipher = AES.new(self.tk_key, AES.MODE_ECB)
        for idx in range(block_len):
            xordata = cipher.encrypt(self.make_CTR_PRELOAD(idx))
            for i, j in zip(xordata, ciphertext[16 * idx: 16 * (idx + 1)]):
                plaintext += bytes([i ^ j])

        return plaintext

    def save_packet(self, name):
        try:
            plaintext = self.decrypt_AES_CTR()
        except Exception as e:
            print(" [*] Error : ", e)

        with open(name , 'wb') as f:
            f.write(plaintext)
        #print("[+] Save Packet Done!")
