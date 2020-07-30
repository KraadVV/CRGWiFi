#sniff module
import threading
import os
import time
import random
from scapy.all import *

class AP_list:
    def __init__(self):
        self.ap_list = []
        self.index = 0

    def add(self, id, ssid, mac, channel): # AP 클래스의 생성자 이용
        a = AP(id, ssid, mac, channel)
        self.ap_list.append(a)

    def __iter__(self): # 클래스를 반복 가능하게 만들기 (for문 사용하기 위해)
        while self.index < len(self.ap_list):
            yield self.ap_list[self.index]
            self.index += 1
        return self

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

aplist = AP_list()

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
    
    def findSSID(pkt): # SSID 찾는 함수
        BSSID = sniffmodule.F_bssids
        if pkt.haslayer(Dot11Beacon): # 패킷이 802.11 비콘 프레임이라면
           mac = pkt.getlayer(Dot11).addr2 # mac주소를 추출하고
           ssid = pkt.getlayer(Dot11Elt).info  # ssid를 추출하고
           if mac not in BSSID: # 해당 bssid가 리스트에 없다면
               if ssid != "" : # ssid가 존재한다면
                   BSSID.append(mac) # 리스트에 추가하고
                   ssid = pkt.getlayer(Dot11Elt).info # ssid를 추출하고
                   channel = int(ord(pkt[Dot11Elt:3].info)) # 그 ap가 존재하는 채널을 추출하고
                   id = int(len(BSSID)) # 잡은 순서대로 ap에 번호를 매겨
                   aplist.add(id, ssid, mac, channel) # AP 클래스 객체로 만들어 AP_list 클래스를 통해 인덱싱

    def scanner(self, iface, sec):
        interface = iface # interface를 wlan0mon으로 하여(모니터 모드 설정 필요)
        thread = threading.Thread(target = sniffmodule.hopper(iface, sec), args=(interface, sec, ), name="hopper") # 서브쓰레드에서 hopper 함수 실행
        thread.daemon = True # 이 서브쓰레드는 데몬쓰레드(메인쓰레드 종료되면 종료)
        thread.start() # 서브쓰레드 시작

        sniff(iface=interface, prn=sniffmodule.findSSID, timeout=sec) # scapy의 sniff 함수 이용, 함수의 인자로 findSSID 함수 사용
        #sniffmodule.stophopper = True
        for a in aplist:
            print(a.id,"번 ap 이름 : ", a.ssid, " mac 주소 : ", a.mac, " 채널 : ", a.channel)
            
        print("end of scan")