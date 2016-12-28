#Packet sniffer in python
#For Linux
from sniffer import Sniffer
import os
import argparse
import sys;

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def initialPrint():
    os.system("toilet -f mono12  idet")

def writeToFile(timestamp, ipsrc, ipdest, lens, layer):
    f = ""
    try:
        f = open('cap.txt', 'a')
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise

    string = "# %s: %s - %s, %s -> %s\n" % (timestamp, ipsrc, ipdest, lens, layer)
    print string
    f.write(string)
    f.close()

def analise():
    try :
        f = open('cap.txt', 'r');
    except:
        raise
    lt = [];

    ipsrc = '192.168.109.140'
    #print ipsrc
    protocolsearchParam = 'SSL'
    sizesearchParam = 1400
    sqlisearchParam = 700
    offset = 200
    setFlag = 0

    for line in f:
        lt.append(line);
    for i in lt:
        pkt = i;
        if setFlag == 1:
            if i.find(protocolsearchParam) != -1:
                i = i.split(',')[1]
                i = i.split()[0]
                if int(i) > sqlisearchParam and int(i) <= (sqlisearchParam + offset):
                        print bcolors.WARNING +  "Probable SQLI on packet" + " " + pkt + bcolors.ENDC
            setFlag = 0
            continue

        if i.find(protocolsearchParam) != -1:
            i = i.split(',')[1]
            i = i.split()[0]
            if int(i) > sizesearchParam and int(i) <= (sizesearchParam + offset):
                setFlag = 1
                continue
    f.close()
    f = open('cap.txt', 'w')
    f.close()


def theCap(count):
    ret = oj.prints(count)
    #writeToFile("12", "127.0.0.1", "10")
    print ("Analysing")
    for pkt in ret:
        try:
            writeToFile(pkt.sniff_timestamp, pkt.ip.src, pkt.ip.dst, pkt.length, pkt.highest_layer)
        except AttributeError:
            print AttributeError
            continue

def defParser():
    blalal = 0
    parser = argparse.ArgumentParser(description='This is a packet sniffer.')
    parser.add_argument('-p', dest = "count", type=int, help=' Capture the P number of packets and save them to the cap.txt file')
    parser.add_argument('-a', dest="blalal", nargs="?", default = 0, help=' Analyse the cap.txt file')

    args = parser.parse_args()
    #print args 1.blalal
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
    #initialPrint()
    #count = defParser()
    '''
    if count == 0:
        analise()
    else:
        theCap(count)
    '''
    while True:
        print "Analysing"
        theCap(30)
        analise()
