#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)
 
import socket, sys, os
from struct import *
 
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

#Important constants for use in the code
VALUE_MB_BYTES = 8*1024*1024
 
# Get the last saved data from the storage
storeFile = "analytics.txt"

destMACMap = {}
sourceMACMap = {}

if storeFile in os.listdir("./"):
    fp = open(storeFile , 'r')
    destMACMap = eval(fp.readline().rstrip())
    sourceMACMap = eval(fp.readline().rstrip())
    fp.close()


recvd = 0
# receive a packet
while True:
    recvd += 1
    if(recvd >= 100):
        #print destMACMap
        #print sourceMACMap
        fp = open(storeFile,'w')
        fp.write(str(destMACMap) + "\n")
        fp.write(str(sourceMACMap))
        fp.close()
        recvd = 0
    packet = s.recvfrom(65565)
    
    #print len(packet)
     
    #packet string from tuple
    packet = packet[0]
    length = len(packet)
     
    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    destMAC = eth_addr(packet[0:6])
    sourceMAC = eth_addr(packet[6:12])

    if (destMACMap.has_key(destMAC) == True):
        destMACMap[destMAC][0] += length / VALUE_MB_BYTES
        destMACMap[destMAC][1] += length % VALUE_MB_BYTES
    else:
        destMACMap[destMAC] = [length / VALUE_MB_BYTES, length % VALUE_MB_BYTES]

    if (sourceMACMap.has_key(sourceMAC) == True):
        sourceMACMap[sourceMAC][0] += length / VALUE_MB_BYTES
        sourceMACMap[sourceMAC][1] += length % VALUE_MB_BYTES
    else:
        sourceMACMap[sourceMAC] = [length / VALUE_MB_BYTES, length % VALUE_MB_BYTES]
    #print 'Destination MAC : ' + destMAC + ' Source MAC : ' + sourceMAC + ' Protocol : ' + str(eth_protocol)
 