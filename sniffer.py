#sniff module
import threading
import os
import time
import random
from scapy.all import *

class AP:
    STA_list = [] # MAC Address of STA connected with target AP
    
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

class STA:
    def __init__(self, id, mac):
        self.id = id
        self.mac = mac
    
    def id(self):
        return self.id
    
    def mac(self):
        return self.mac

class sniffmodule():

    F_bssids = []    # Found BSSIDs
    F_APs = []
    F_STAs = []
    interface = ""
    target_id = 1
    stop_hopper = False

    def __init__(self, interface):
        self.interface = interface

    def hopper(self, sec): # 채널 돌리는 함수
        n = 1 # 채널 1에서 시작
        #stop_hopper = sniffmodule.stophopper #at here,p found issue that hopper not stop.
        while not self.stop_hopper:
            time.sleep(0.50) # 프로세스 0.5초 정지
            print("  [*] channel set to %d" % n)
            os.system('iwconfig %s channel %d' % (self.interface, n)) # 리눅스 명령어 이용, 채널변경
            dig = int(random.random() * 14) # 안겹치게 채널 무작위로 변경
            if dig != 0 and dig != n:
                n = dig
    
    def findAP(self, pkt): # SSID 찾는 함수
        if pkt.haslayer(Dot11Beacon): # 패킷이 802.11 비콘 프레임이라면
            mac = pkt.getlayer(Dot11).addr2 # mac주소를 추출하고
            ssid = pkt.getlayer(Dot11Elt).info  # ssid를 추출하고
            if mac not in self.F_bssids: # 해당 bssid가 리스트에 없다면
                if ssid != "" and sum(list(ssid)) != 0 : # ssid가 존재한다면
                    ssid = pkt.getlayer(Dot11Elt).info # ssid를 추출하고
                    try:
                        channel = int(ord(pkt[Dot11Elt:3].info)) # 그 ap가 존재하는 채널을 추출하고
                    except:
                        return
                    self.F_bssids.append(mac) # 리스트에 추가하고
                    id = int(len(self.F_bssids)) # 잡은 순서대로 ap에 번호를 매겨
                    a = AP(id, ssid, mac, channel)
                    self.F_APs.append(a)
    
    def select_target(self) :        
        target = int(input(' [*] give me target id : ')) - 1
        self.target_id = target
        
    
    def findSTA(self, pkt) :
        if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
            # This means it's data frame.

            sn = pkt.getlayer(Dot11).addr2
            rc = pkt.getlayer(Dot11).addr1

            i = self.target_id
            target_mac = self.F_APs[i].mac
            maclist = self.F_APs[i].STA_list
            tempid = int(len(self.F_STAs))
            if sn == target_mac and rc not in maclist :
                tmp = STA(len(tempid), rc)
                self.F_STAs.append(tmp)
                maclist.append(rc)
            elif rc == target_mac and sn not in maclist :
                tmp = STA(len(self.F_STAs), sn)
                self.F_STAs.append(tmp)
                maclist.append(sn)

            # Update

            self.F_APs[i].STA_list = maclist

    def AP_scanner(self, sec):
        try:
            thread = threading.Thread(target = self.hopper, args=(sec, ), name="hopper")
            thread.daemon = True
            thread.start()       

            sniff(iface=self.interface, prn=self.findAP, timeout=sec)

        except Exception as e: # False Case 1 [Hopper or Sniff Failed]
            print(" [*] Error : ", e)
            return False

        finally:
            self.stop_hopper = True

        if len(self.F_APs) == 0:
            # False Case 2 [AP Scan Failed]
            return False
        
        # Success   
        print(" [+] AP Scan Completed")
        return True
        
    def STA_scanner(self, sec) :
        aplist = self.F_APs
        i = self.target_id
        n = aplist[i].channel
        os.system('iwconfig %s channel %d' % (self.interface, n))
        
        try:
            sniff(iface=self.interface, prn=self.findSTA, timeout=sec)
        except Exception as e: # False Case 1
            print(" [*] Error : ", e)
            return False
        
        if len(self.F_STAs) == 0:
            # False Case 2 [STA Scan Failed]
            return False

        # Success
        print(" [+] STA Scan Completed!")
        return True
        
