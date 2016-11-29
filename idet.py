#Packet sniffer in python
#For Linux
from sniffer import Sniffer
import os
import argparse

def initialPrint():
    os.system("toilet -f mono12  idet")

def writeToFile(timestamp, ipsrc, len):
    f = ""
    try:
        f = open('cap.txt', 'a')
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise

    string = "# %s: %s, %s\n" % (timestamp, ipsrc, len)
    f.write(string)
    f.close()

def analise():
    print "analysing"


def theCap(count):
    ret = oj.prints(count)
    #writeToFile("12", "127.0.0.1", "10")
    for pkt in ret:
        writeToFile(pkt.sniff_timestamp, pkt.ip.src, pkt.length)

def defParser():
    blalal = 0
    parser = argparse.ArgumentParser(description='This is a packet sniffer.')
    parser.add_argument('-p', dest = "count", type=int, help=' Capture the P number of packets and save them to the cap.txt file')
    parser.add_argument('-a', dest="blalal", nargs="?", default = 0, help=' Analyse the cap.txt file')

    args = parser.parse_args()
    #print args.blalal
    #print args.count
    if args.count == 0:
        raise Exception('Packet Value Capture not set.')
    if args.blalal != 0:
        return 0
    else:
        #print args.count
        return args.count
if __name__ == "__main__":
    oj = Sniffer("wlan0")
    initialPrint()
    count = defParser()
    if count == 0:
        analise()
    else:
        theCap(count)
