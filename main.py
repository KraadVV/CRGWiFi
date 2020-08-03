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

a = monCheck.MonitorCheck()
s = sniffer.sniffmodule()
iwName = a.iwName
iwStatus = a.monitorStatus

if iwStatus != True:
    print("No Monitor interface Detected")
    sys.exit()

#test line
'''
for argv in sys.argv:
    print('arg value = ', argv)
'''

#switch here, activate module
#try:
if sys.argv[1] =="-s":
    print("scanner mode active")
    sec = int(input("set time to scan: "))
    s.AP_scanner(iwName, sec)
    s.select_target()
    sec = int(input("set time to scan: "))
    s.STA_scanner(iwName, sec)
    print("scan complete")

elif sys.argv[1] == "-c":
    print("capture mode active")

elif sys.argv[1] == "-e":
    print("extract mode active")

elif sys.argv[1] == "-h":
    print("usage:\n")
    print("scanner mode : main.py -s\n")
    print("you can scan nearby STA and AP\n\n")
    print("capture mode : main.py -c target_AP_MAC target_STA_MAC AP_password\n")
    print("you can capture packet between target AP and STA and save to PCAP file\n\n")
    print("extract mode : main.py -e pcap_file_name -t [jpeg/pdf/avi]\n")
    print("you can extract file from captured pcap file\n")

else:
    print("invalid operation ", argv[1])
    print("try main.py -h to view more help")

'''except:
    print("unknown error detected: process ceased")'''
