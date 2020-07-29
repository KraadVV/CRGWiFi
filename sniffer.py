
import threading
import os
import time
import random
from scapy.all import *

class sniffmodule():
    stophopper = False
    def hopper(iface): # 채널 돌리는 함수
        #n = 1 # 채널 1에서 시작
        #stop_hopper = sniffmodule.stophopper //at here, found issue that hopper not stop.
        #while not stop_hopper:
        for n in range(1,14):
            time.sleep(0.50) # 프로세스 0.5초 정지
            os.system('iwconfig %s channel %d' % (iface, n)) # 리눅스 명령어 이용, 채널변경
            dig = int(random.random() * 14) # 안겹치게 채널 무작위로 변경
            if dig != 0 and dig != n:
                n = dig

    F_bssids = []    # Found BSSIDs

    def findSSID(pkt): # SSID 찾는 함수
        BSSID = sniffmodule.F_bssids
        if pkt.haslayer(Dot11Beacon): # 패킷이 802.11 비콘 프레임이라면
           if pkt.getlayer(Dot11).addr2 not in BSSID: # 해당 bssid가 리스트에 없다면
               BSSID.append(pkt.getlayer(Dot11).addr2) # 리스트에 추가하고
               ssid = pkt.getlayer(Dot11Elt).info # ssid를 추출하고
               channel = int(ord(pkt[Dot11Elt:3].info)) # 그 ap가 존재하는 채널을 추출하여
               print("Network Detected:", ssid, ", on channel ", channel) # 출력한다

    def scanner(self, iface):
        interface = iface # interface를 wlan0mon으로 하여(모니터 모드 설정 필요)
        thread = threading.Thread(target = sniffmodule.hopper(iface), args=(interface, ), name="hopper") # 서브쓰레드에서 hopper 함수 실행
        thread.daemon = True # 이 서브쓰레드는 데몬쓰레드(메인쓰레드 종료되면 종료)
        thread.start() # 서브쓰레드 시작

        sniff(iface=interface, prn=sniffmodule.findSSID, timeout=5) # scapy의 sniff 함수 이용, 함수의 인자로 findSSID 함수 사용
        sniffmodule.stophopper = True
        print("end of scan")

