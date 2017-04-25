#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)
 
import socket, sys, os, threading, time
from struct import *
 
class myThread (threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
    def run(self):
        print "Starting " + self.name
        update_file(self.name)
        # Get lock to synchronize threads
        #threadLock.acquire()
        #print_time(self.name, self.counter, 3)
        # Free lock to release next thread
        #threadLock.release()


def update_file(threadName):
    global destMACMap
    global sourceMACMap
    global storeFile
    copyDestMACMap = {}
    copySourceMACMap = {}
    while(True):
        time.sleep(2)
        threadLock.acquire()
        copyDestMACMap = destMACMap
        copySourceMACMap = sourceMACMap
        threadLock.release()
        #print "Writing data to file: " + str(copyDestMACMap) + " " + str(copySourceMACMap)
        fp = open(storeFile,'w')
        fp.write(str(copyDestMACMap) + "\n")
        fp.write(str(copySourceMACMap))
        fp.close()


#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
threadLock = threading.Lock()

print "Creating socket"
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

print "Socket Created"
#Important constants for use in the code
VALUE_MB_BYTES = 1024*1024
 
# Get the last saved data from the storage
storeFile = "analytics.txt"

destMACMap = {}
sourceMACMap = {}

if storeFile in os.listdir("./"):
    fp = open(storeFile , 'r')
    destMACMap = eval(fp.readline().rstrip())
    sourceMACMap = eval(fp.readline().rstrip())
    fp.close()


thread1 = myThread(1, "BackinUpThread", 2)
thread1.start()
print "Backing Up Thread Started"

print "Continuing main thread loop"
# receive a packet
while True:
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

    threadLock.acquire()
    if (destMACMap.has_key(destMAC) == True):
        destMACMap[destMAC][1] += length
        destMACMap[destMAC][0] += destMACMap[destMAC][1] / VALUE_MB_BYTES
        destMACMap[destMAC][1] = destMACMap[destMAC][1] % VALUE_MB_BYTES
    else:
        destMACMap[destMAC] = [length / VALUE_MB_BYTES, length % VALUE_MB_BYTES]

    if (sourceMACMap.has_key(sourceMAC) == True):
        sourceMACMap[sourceMAC][1] += length
        sourceMACMap[sourceMAC][0] += sourceMACMap[sourceMAC][1] / VALUE_MB_BYTES
        sourceMACMap[sourceMAC][1] = sourceMACMap[sourceMAC][1] % VALUE_MB_BYTES
    else:
        sourceMACMap[sourceMAC] = [length / VALUE_MB_BYTES, length % VALUE_MB_BYTES]

    threadLock.release()
    #print 'Destination MAC : ' + destMAC + ' Source MAC : ' + sourceMAC + ' Protocol : ' + str(eth_protocol)
 