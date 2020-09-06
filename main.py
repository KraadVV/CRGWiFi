import sys
import monCheck
import scanner
import texttable
import time
import wpa2decryption

from datetime import datetime

'''
without argv: print help
scanner mode: print nearby AP and STA
-argv type: main.py -s or --scanner
-result: print SSID \t MAC \t channel
on AP and STA nearvy
capture mode: sniff&decode target STA&AP
-argv type: main.py -c target_ap_mac target_STA_mac password
-do: reset connection btween target AP and STA, capture auth packet, decode wpa2 encoded packet, save to pcap file
-result: abc.pcap
extract mode: extract img/pdf/or something...
-argv type: main.py -e abc.pcap
'''

def help():
    print("""Public WiFi HACK!

Usage:
  crgwifi.py -s
  crgwifi.py -e
  crgwifi.py -c AP_MAC STA_MAC -o <Save_Dir>
  crgwifi.py -h | --help
  crgwifi.py --version

Options:
  -s		Scan mode. Scan all AP and STA.
  -c		Capture mode. When Authentication packet arrive, it automatically decrypt and save packets.
  -h --help     Show this screen.
  --version     Show version.""")
  
  
if __name__== '__main__':

    isScannerActive = False
    isCaptureActive = False
    isExtracterActive = False

    if sys.argv[1] == "-s":
        isScannerActive = True
    elif sys.argv[1] == "-c":
        isCaptureActive = True
    elif sys.argv[1] == "-e":
        isExtracterActive = True


    a = monCheck.MonitorCheck()
    iwName = a.iwName
    iwStatus = a.monitorStatus
    
    if iwStatus != True:
        print("No Monitor interface Detected")
        sys.exit()
    
    if len(sys.argv) < 2:
    	help()
    
    elif isScannerActive == True:
        # Init
        s = scanner.sniffmodule(iwName)
        print("[+] Scanner mode active")
        
        # AP Scan Start
        sec = int(input(" [+] AP Scan - Set time to scan: "))
        result = s.AP_scanner(sec)
        if not result:
            print(" [*] AP scan Failed...")
            sys.exit()
        time.sleep(1)
        
        # Print Result as Table
        AP = s.F_APs     
        ta= texttable.Texttable()
        ta.add_row(['id', 'SSID', 'mac'])
        for aps in AP:
            ta.add_row([aps.id, aps.ssid, aps.mac])
        print(ta.draw())
            
        
        # STA Scan Start    
        s.select_target()
        sec = int(input(" [+] STA Scan - Set time to scan: "))
        result2 = s.STA_scanner(sec)
        if not result2:
            print(" [*] STA scan Failed...")
            sys.exit()
            
        # Print Result as Table
        STA = s.F_STAs
        ts = texttable.Texttable()
        ts.add_row(['id', 'mac'])
        for stas in STA:
            ts.add_row([stas.id+1, stas.mac])
        print(ts.draw())

        print("[+] Enter capture mode? Y/N")
        IsCaptureActive = input()
        IsCaptureActive.lower()
        while True:
            try:
                if IsCaptureActive =="y":
                    isCaptureActive == True
                    break
                elif IsCaptureActive =="n":
                    print("[+] Exit System")
                    sys.exit()
                else:
                    continue
            except:
                print("[+] Error occured. please type again")
                continue


    
    elif isCaptureActive == True:
        print("[+] capture mode active")

        if isScannerActive == False:
            try:
                AP_MAC = sys.argv[2]
                STA_MAC = sys.argv[3]
            except:
                print("[+] MAC Error occured: please enter accurate MAC Address")
                print("[+] AP MAC: ")
                AP_MAC = input()
                print("[+] STA MAC: ")
                STA_MAC = input()

        #대충 캡처해서 저장하는 부분이 들어갈 위

        #save file location
        now = datetime.now()
        TimeInfo = now.year+"_"+now.month+"_"+now.day+"_"+now.hour+"_"+now.minute
        FileLocation = "./Capture_"+TimeInfo #세이브파일 형식은 캡처_현재시각의 형태, 요 위치에 저장하도록 코드 짜길 요망

    
    elif isExtracterActive == True:
        print("[+] extract mode active")
        if isScannerActive == False:
            try:
                FileLocation = sys.argv[2]
            except:
                print("[+] File Location Error: please type correct file location")
                FileLocation = input("[+] File Location: ")

        wpa2decryption.decrypt(FileLocation) # 파일 로케이션을 인자로 받아서 돌리게끔 함

    
    elif sys.argv[1] == "-h":
        help()
    
    else:
        print("[+] invalid operation: ", sys.argv[1])
        print("[+] try crgwifi.py -h to view more help")

'''except:
    print("unknown error detected: process ceased")'''
