from scapy.all import *
import binascii
import wpa2decryption
    
class Capturemodule:    
    def __init__(self, APmac, STAmac, ssid, pw, interface, SAVE_FOLDER):
        self.APmac = APmac
        self.STAmac = STAmac
        self.ssid = ssid
        self.pw = pw
        self.interface = interface
        self.SAVE_FOLDER = SAVE_FOLDER
        self.sequence = 0
        self.status = 0
        """
        [STATUS]
        Bits 1 authentication request
        Bits 2 authentication response
        Bits 4 association request
        Bits 8 association response
        Bits 16 key_ex1_done
        Bits 32 key_ex2_done
        """
    
    def deauth(self):
        dot11 = Dot11(addr1= self.STAmac, addr2= self.APmac, addr3= self.APmac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        sendp(packet, count=1, iface= self.interface, verbose=1)
        
    def packet_sniff(self):
        sniff(iface=self.interface, prn=self.mac_filter)

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
        if pkt.getlayer(Dot11AssoResp).status == 0:  # status 0 : success
            self.status |= 8
            print(" [*] Association Response")

    def eapol_keychange(self, pkt):
        eapol = bytes(pkt.getlayer(EAPOL))
        key_information_field = eapol[5:7]

        # Key Message Number : 1
        if key_information_field == b'\x00\x8a':
            print(" [*] EAPOL key change : Start")
            self.aNonce = eapol[0x11 : 0x11 + 0x20]
            self.status |= 16

        # Key Message Number : 2
        elif key_information_field == b'\x01\x0a':
            self.sNonce = eapol[0x11 : 0x11 + 0x20]

            APmac = binascii.a2b_hex(self.APmac.replace(":", ""))
            STAmac = binascii.a2b_hex(self.STAmac.replace(":", ""))

            getptk = wpa2decryption.GetPTK(self.ssid, self.pw, self.aNonce, self.sNonce, APmac, STAmac)
            self.tk_key = getptk.tk_key
            self.status |= 32
            print(" [*] EAPOL key change : Done")                          

        # Key Message Number : 3(b'\x13\xca'), 4(b'\x03\x0a')
        else:
            pass

    def collect_data(self, pkt):
        if self.sequence == 0:
            print(" [*] Collecting data")
        self.sequence += 1 

        wpa2decryptionbox = wpa2decryption.WPA2DecryptionBox(pkt, self.tk_key)

        if wpa2decryptionbox.check_CCMP(): # In Some case, Group Cipher suite is TKIP..
            wpa2decryptionbox.setting()
            wpa2decryptionbox.save_packet(self.SAVE_FOLDER + "/result_" + str(self.sequence))


if __name__ == '__main__':
    # Just For test.... Packet capture is too hard...
    sample = PcapReader("/home/hunjison/Desktop/wpa-Induction.pcap")  # Pcap From Wireshark
    pkt_list = sample.read_all()
    SAVE_FOLDER = './packet/'
    capturemodule = Capturemodule('00:0d:93:82:36:3a', '00:0c:41:82:b2:55', 'Coherer', 'Induction', 'interface', SAVE_FOLDER)
    for pkt in pkt_list:
        capturemodule.mac_filter(pkt)
