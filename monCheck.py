#module that checks iface monitor mode
import subprocess
import sys

class MonitorCheck():
    iwsys = 'iwconfig'
    popen = subprocess.Popen("iwconfig", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()
    iwConMessage = popen[0].decode()

    MonitorIdx = iwConMessage.find('Monitor')
    if MonitorIdx == -1:
        print("No Monitor mode Found")
        monitorStatus = False
        sys.exit()

    #cut down pace: find Monitor interface name
    iwConTemp = iwConMessage[:MonitorIdx]
    iwConTempRev = iwConTemp[::-1]
    MonitorIwIdx = iwConTempRev.find('\n')
    if MonitorIwIdx != -1:
        iwConTempRev = iwConTempRev[:MonitorIwIdx]
    iwFinal = iwConTempRev[::-1]
    iwName = iwFinal[:iwFinal.find('  IEEE')].strip()

    monitorStatus = True
