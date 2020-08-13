import sys
import monCheck
import sniffer

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

    a = monCheck.MonitorCheck()
    iwName = a.iwName
    iwStatus = a.monitorStatus
    
    if iwStatus != True:
        print("No Monitor interface Detected")
        sys.exit()
    
    if len(sys.argv) < 2:
    	help()
    
    elif sys.argv[1] =="-s":
        s = sniffer.sniffmodule(iwName)
        print("scanner mode active")
        
        sec = int(input("set time to scan: "))
        result = s.AP_scanner(sec)
        if not result:
            print("AP scan Failed...")
            sys.exit()
        s.select_target()
        
        sec = int(input("set time to scan: "))
        s.STA_scanner(sec)
        print("scan complete")
    
    elif sys.argv[1] == "-c":
        print("capture mode active")
    
    elif sys.argv[1] == "-e":
        print("extract mode active")
    
    elif sys.argv[1] == "-h":
        help()
    
    else:
        print("invalid operation ", argv[1])
        print("try main.py -h to view more help")

'''except:
    print("unknown error detected: process ceased")'''
