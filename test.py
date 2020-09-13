import capture
import binascii

SSID = 'U+Net94D8'
PW = '1152001440'
ap_mac = '08:5d:dd:08:94:d6'
s_mac = '08:71:90:89:b4:80'
#ap_mac = binascii.a2b_hex('085ddd0894d6')
#s_mac = binascii.a2b_hex('08719089b480')

c = capture.capturemodule()
iwname = 'wlan0mon'
apch = 4

c.capture4way(s_mac, ap_mac, iwname, apch, 10)
anonce = c.F_nonces[0]
snonce = c.F_nonces[1]

ap_mac = binascii.a2b_hex(ap_mac.replace(":",""))
s_mac = binascii.a2b_hex(s_mac.replace(":",""))

A, B = c.MakeAB(anonce, snonce, ap_mac, s_mac)
pmk = c.makePMK(PW, SSID)
ptk = c.makePTK(pmk, A, B)

print(ptk)