import os
import sys

class MonitorCheck():
    iwsys = 'iwconfig'
    iwConMessage = os.popen(iwsys).read()

    MonitorIdx = iwConMessage.find('Monitor')

    if MonitorIdx == -1:
        print("No Monitor mode Found")
        monitorStatus = False
        sys.exit()

    #cut down pace: find Monitor interface name
    iwConTemp = iwConMessage[:MonitorIdx]
    iwConTempRev = iwConTemp[::-1]
    MonitorIwIdx = iwConTempRev.find('\n')
    iwConTempRev2 = iwConTempRev[:MonitorIwIdx]
    iwFinal = iwConTempRev2[::-1]
    iwName = iwFinal[:iwFinal.find('  IEEE')]

    monitorStatus = True
