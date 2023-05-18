from network import WLAN, AP_IF, STA_IF
from espnow import ESPNow
from sys import platform
from CryptoXo import Crypt

# A WLAN AP interface disable
ap = WLAN(AP_IF)
ap.active(False)

# A WLAN STA interface must be active to send()/recv()
sta = WLAN(STA_IF)
# sta.config(channel=3) # does not work with esp32-s3
sta.active(True)
sta.disconnect()  # disconnect from previous connection

# node mac address and node identifier
MAC = sta.config('mac')
NID = "%s-%d-%d" % (platform, hash(MAC)%254, hash(MAC)%42)

# Now setup ESPNOW
ew = ESPNow()
ew.active(True)

# Set the Primary Master Key (PMK) which is used to encrypt the 
# Local Master Keys (LMK) for encrypting ESPNow data traffic.
# Must be 16Bytes long
ew.set_pmk(b'AdsTuiPo10J10lmt') # not sure it is working

BAS = b'\xff'*6
ew.add_peer(BAS)

# encryption functions
crypt = Crypt() # only one object - not thread save!

def encrypt(mac):
   crypt.key(mac, 'HSGT 17ysg#1nsv0= hst!!')
   return crypt.encrypt

def decrypt(mac):
   crypt.key(mac, 'HSGT 17ysg#1nsv0= hst!!')
   return crypt.decrypt

# usage:
# from espnow_init import MAC, NID, BAS, ew, encrypt, decrypt 
#
# where:
#    MAC - node mac address 
#    NID - unique node identifier
#    BAS - broadcast mac address
#    ew  - espnow object
#    encrypt - encryption function after new key
#    decrypt - decryption function after new key
