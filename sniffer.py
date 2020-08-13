#sniff module
import threading
import os
import time
import random
from scapy.all import *

class AP:
    def __init__(self, id, ssid, mac, channel):
        self.id = id
        self.ssid = ssid
        self.mac = mac
        self.channel = channel

    def id(self): # id 불러오기
        return self.id

    def ssid(self): # ssid 불러오기
        return self.ssid

    def mac(self): # mac 불러오기
        return self.mac

    def channel(self): # channel 불러오기
        return self.channel


class sniffmodule():

    F_bssids = []    # Found BSSIDs
    F_APs = []
    F_STAs = []
    interface = ""
    target_id = 1

    def __init__(self, interface):
        self.interface = interface

    def hopper(self, sec): # 채널 돌리는 함수
        n = 1 # 채널 1에서 시작
        #stop_hopper = sniffmodule.stophopper #at here,p found issue that hopper not stop.
        #while not stop_hopper:
        for a in range((sec*2)+2):
            time.sleep(0.50) # 프로세스 0.5초 정지
            print("[+] channel set to %d" % n)
            os.system('iwconfig %s channel %d' % (self.interface, n)) # 리눅스 명령어 이용, 채널변경
            dig = int(random.random() * 14) # 안겹치게 채널 무작위로 변경
            if dig != 0 and dig != n:
                n = dig
    
    def findAP(self, pkt): # SSID 찾는 함수
        if pkt.haslayer(Dot11Beacon): # 패킷이 802.11 비콘 프레임이라면
            mac = pkt.getlayer(Dot11).addr2 # mac주소를 추출하고
            #print("[+] mac : " , mac)
            ssid = pkt.getlayer(Dot11Elt).info  # ssid를 추출하고
            #print("[+] ssid : " , ssid)
            if mac not in self.F_bssids: # 해당 bssid가 리스트에 없다면
                if ssid != "" and sum(list(ssid)) != 0 : # ssid가 존재한다면
                    ssid = pkt.getlayer(Dot11Elt).info # ssid를 추출하고
                    #print("[+] info : " , pkt[Dot11Elt:3].info)
                    try:
                        channel = int(ord(pkt[Dot11Elt:3].info)) # 그 ap가 존재하는 채널을 추출하고
                    except:
                        return
                    self.F_bssids.append(mac) # 리스트에 추가하고
                    id = int(len(self.F_bssids)) # 잡은 순서대로 ap에 번호를 매겨
                    a = AP(id, ssid, mac, channel)
                    self.F_APs.append(a)
    
    def select_target(self) :
        target = int(input('give me target id : ')) - 1
        self.target_id = target
        
    
    def findSTA(self, pkt) :
        if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
            print("[+] Data Packet Pass!") 
            # This means it's data frame.
            sn = pkt.getlayer(Dot11).addr2.upper()
            rc = pkt.getlayer(Dot11).addr1.upper()

            i = self.target_id
            target_mac = self.F_APs[i].mac.upper()
            print(" [-] sn : " , sn, ", rc : ", rc, ", target_mac : " + target_mac)

            if sn == target_mac and rc not in self.F_STAs :
                self.F_STAs.append(rc)
                print(" [-] Append 1")
            elif rc == target_mac and sn not in self.F_STAs :
                self.F_STAs.append(sn)
                print(" [-] Append 2")
            print(" [-] Station List!", self.F_STAs)

    def AP_scanner(self, sec):
        try:
            thread = threading.Thread(target = self.hopper, args=(sec, ), name="hopper")
            thread.daemon = True
            thread.start()       

            sniff(iface=self.interface, prn=self.findAP, timeout=sec)
            #sniffmodule.stophopper = True

        except Exception as e: # False Case 1 [Hopper or Sniff Failed]
            print("Error : ", e)
            return False

        if len(self.F_APs) == 0:
            # False Case 2 [AP Scan Failed]
            return False

        for a in self.F_APs:
            print(a.id,"번 ap 이름 : ", a.ssid, " mac 주소 : ", a.mac, " 채널 : ", a.channel)
            
        print("end of scan")
        # Success
        return True
        
    def STA_scanner(self, sec) :
        aplist = self.F_APs
        i = self.target_id
        n = aplist[i].channel
        os.system('iwconfig %s channel %d' % (self.interface, n))
        
        sniff(iface=self.interface, prn=self.findSTA, timeout=sec)

        for a in self.F_STAs:
            print(a)

        print("end of scan")
