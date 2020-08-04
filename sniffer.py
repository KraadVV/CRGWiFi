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
    #stophopper = False

    def hopper(iface, sec): # 채널 돌리는 함수
        n = 1 # 채널 1에서 시작
        #stop_hopper = sniffmodule.stophopper #at here, found issue that hopper not stop.
        #while not stop_hopper:
        for a in range((sec*2)+2):
            time.sleep(0.50) # 프로세스 0.5초 정지
            os.system('iwconfig %s channel %d' % (iface, n)) # 리눅스 명령어 이용, 채널변경
            dig = int(random.random() * 14) # 안겹치게 채널 무작위로 변경
            if dig != 0 and dig != n:
                n = dig

    F_bssids = []    # Found BSSIDs
    F_APs = []
    target_id = 1
    
    def findAP(pkt): # SSID 찾는 함수
        BSSID = sniffmodule.F_bssids
        aplist = sniffmodule.F_APs
        if pkt.haslayer(Dot11Beacon): # 패킷이 802.11 비콘 프레임이라면
           mac = pkt.getlayer(Dot11).addr2 # mac주소를 추출하고
           ssid = pkt.getlayer(Dot11Elt).info  # ssid를 추출하고
           if mac not in BSSID: # 해당 bssid가 리스트에 없다면
               if ssid != "" and sum(list(ssid)) != 0 : # ssid가 존재한다면
                   BSSID.append(mac) # 리스트에 추가하고
                   ssid = pkt.getlayer(Dot11Elt).info # ssid를 추출하고
                   channel = int(ord(pkt[Dot11Elt:3].info)) # 그 ap가 존재하는 채널을 추출하고
                   id = int(len(BSSID)) # 잡은 순서대로 ap에 번호를 매겨
                   a = AP(id, ssid, mac, channel)
                   aplist.append(a)
    
    def select_target(self) : # 잡은 AP 중에서 타겟 선정
        sniffmodule.target_id = int(input('give me target id : '))
        
    F_STAs = []
    
    def findSTA(pkt) :
        if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
            # 802.11 패킷이며, 연결이 성사된 데이터 프레임이고, 실패한 인증 패킷이 아닌 경우에만
            sn = pkt.getlayer(Dot11).addr2.upper() # 송신자 맥주소
            rc = pkt.getlayer(Dot11).addr1.upper() # 수신자 맥주소

            aplist = sniffmodule.F_APs
            stalist = sniffmodule.F_STAs
            i = sniffmodule.target_id
            target_mac = aplist[i-1].mac # 선정한 타겟 AP의 맥주소 정보 가져오기
            #print(target_mac)
            if sn == target_mac and rc not in stalist :
                stalist.append(rc)
            elif rc == target_mac and sn not in stalist :
                stalist.append(sn)


    def AP_scanner(self, iface, sec):
        interface = iface # interface를 wlan0mon으로 하여(모니터 모드 설정 필요)
        thread = threading.Thread(target = sniffmodule.hopper(iface, sec), args=(interface, sec, ), name="hopper") # 서브쓰레드에서 hopper 함수 실행
        thread.daemon = True # 이 서브쓰레드는 데몬쓰레드(메인쓰레드 종료되면 종료)
        thread.start() # 서브쓰레드 시작

        sniff(iface=interface, prn=sniffmodule.findAP, timeout=sec) # scapy의 sniff 함수 이용, 함수의 인자로 findAP 함수 사용
        #sniffmodule.stophopper = True
        aplist = sniffmodule.F_APs
        for a in aplist:
            print(a.id,"번 ap 이름 : ", a.ssid, " mac 주소 : ", a.mac, " 채널 : ", a.channel)
            
        print("end of scan")
        
    def STA_scanner(self, iface, sec) :
        interface = iface
        aplist = sniffmodule.F_APs
        i = sniffmodule.target_id # 선정한 타겟 AP의 채널정보 가져오기
        n = aplist[i-1].channel
        #print(n)
        os.system('iwconfig %s channel %d' % (iface, n)) # 채널 고정!
        
        '''for channel in range(1,14) :
            os.system('iwconfig %s channel %d' % (iface, channel))'''
        sniff(iface=interface, prn=sniffmodule.findSTA, timeout=sec)
            
        stalist = sniffmodule.F_STAs
        for a in stalist:
            print(a)

        print("end of scan")