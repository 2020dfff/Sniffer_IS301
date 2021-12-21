import sys
from scapy.all import *

def packetHandler(pkt):
    print(pkt)

sniff(filter="tcp", iface="ens33", prn=packetHandler)

print("1111")
# sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))
# a = IP(ttl = 100)
# print(a.src)
