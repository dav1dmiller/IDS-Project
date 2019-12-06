from scapy.all import *
import logging
import re
from enum import Enum
import io
import sys
from threading import Thread
from Rule import *
import RuleFileReader

class Sniffer(Rule):
    def __init__(self, ruleList):
        #Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList

    def stop(self):
        self.stopped = True
    def stopfilter(self, x):
        return self.stopped

    def inPkt(self, pkt):
        for rule in self.ruleList:
            #Check all rules
            # print "checking rule"
            matched = self.match(pkt)
            if(matched):
                print("=======================WARNING=======================")
    def run(self):
        print("Sniffing has started...")
        sniff(filter="", prn=self.inPkt, store=0, stop_filter=self.stopfilter)


    def match(self, pkt):
         # print("Checking for any packets that match a rule...")
        """To prevent false positives we need to ensure that all parts of the packet match one of our rules"""
        """This is where checking the correct parameters is critical"""
        # Redirect output of print to the variable capture
        capture = io.StringIO()
        save_stdout = sys.stdout
        sys.stdout = capture
        pkt.show()
        sys.stdout = save_stdout

        # Capture is now a string with output of pkt.show()
        str=capture.getvalue()
        str1=str
        """strip away all spaces tabs and"""
        str=re.sub(r"[\t' ']*", "", str)
        token=str.split("\n")

        #print(str1)
        #Assign values
        scapy_header=token[0]
        if(scapy_header=="###[Ethernet]###" and len(token) > 28):
            try:
                dst_mac=token[1].replace("dst=", "")
            except:
                raise ValueError("Invalid rule: incorrect value for dst_mac " + token[1])

            try:
                src_mac=token[2].replace("src=", "")
            except:
                raise ValueError("Invalid rule: incorrect value for src_mac " + token[2])

            try:
                 ip_type = token[3].replace("type=", "")
            except:
                 raise ValueError("Invalid rule: incorrect value for ip_type " + token[3])

            try:
                 ip_header = token[4]
                 #print(ip_header)
            except:
                 raise ValueError("Invalid rule: incorrect value for ip_header " + token[4])
            try:
                 ip_version = token[5]
                 #print(ip_header)
            except:
                 raise ValueError("Invalid rule: incorrect value for ip_version " + token[5])
            try:
                 ihl = token[6]
                 #print(ip_header)
            except:
                 raise ValueError("Invalid rule: incorrect value for ihl " + token[6])
            try:
                 tos = token[7]
                 #print(ip_header)
            except:
                 raise ValueError("Invalid rule: incorrect value for tos " + token[7])
            try:
                length = token[8]
                #print(ip_header)
            except:
                 raise ValueError("Invalid rule: incorrect value for len " + token[8])

            try:
                id = token[9]
            except:
                 raise ValueError("Invalid rule: incorrect value for id " + token[9])

            try:
                 flag = token[10].replace("flag=", "")
            except:
                 raise ValueError("Invalid rule: incorrect value for flag " + token[10])

            try:
                protocol_type=token[13].replace("proto=", "")
                #print("PROTO: " + protocol_type)
            except:
                raise ValueError("Invalid rule: incorrect value for proto " + token[13])
            try:
                ip_checksum=token[14].replace("chksum=", "")
            except:
                raise ValueError("Invalid rule: incorrect value for ip_checksum " + token[14])
            #if(token[15].__contains__("src=")):
            try:
                src_ip=token[15].replace("src=", "")
                #print("SRC IP: " + src_ip)
            except:
                raise ValueError("Invalid rule: incorrect value for src_ip " + token[15])

            try:
                dst_ip = token[16].replace("dst=", "")
                #print("DST IP: " + dst_ip)
            except:
                raise ValueError("Invalid rule: incorrect value for dst_ip " + token[16])

            pkt_header=token[18]

            try:
                sport=token[19].replace("sport=", "")
            except:
                raise ValueError("Invalid rule: incorrect value for sport " + token[19])
            try:
                 dport = token[20].replace("dport=", "")
            except:
                 raise ValueError("Invalid rule: incorrect value for sport " + token[20])
            try:
                 seq = token[21].replace("seq=", "")
            except:
                 raise ValueError("Invalid rule: incorrect value for seq " + token[21])
            try:
                 ack = token[22].replace("ack=", "")
                 #print(ack)
            except:
                 raise ValueError("Invalid rule: incorrect value for ack " + token[22])
            try:
                 pkt_flags = token[25].replace("flags=", "")
            except:
                 raise ValueError("Invalid rule: incorrect value for pkt_flags " + token[25])
            try:
                 window = token[26].replace("window=", "")
            except:
                 raise ValueError("Invalid rule: incorrect value for window " + token[26])
            try:
                 pkt_checksum = token[27].replace("chksum=", "")
            except:
                 raise ValueError("Invalid rule: incorrect value for pkt_checksum " + token[27])
            try:
                 urgptr = token[28].replace("urgptr=", "")
            except:
                 raise ValueError("Invalid rule: incorrect value for urgptr " + token[28])

            """Check for matches between the rules and the incoming packets"""
            """"While we have rules to check. check rules"""
            for i in range(0, len(RuleFileReader.rulelist)):
                #print(RuleFileReader.rulelist[i].protocol_type)
                if(protocol_type != RuleFileReader.rulelist[i].protocol_type):
                    return False
                elif(pkt_flags != RuleFileReader.rulelist[i].flag):
                    return False
                elif(urgptr != RuleFileReader.rulelist[i].urgent):
                    return False
                elif(length != RuleFileReader.rulelist[i].src_bytes):
                    return False
                else:
                    return True





