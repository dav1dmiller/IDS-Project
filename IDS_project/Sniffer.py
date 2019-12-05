from scapy.all import *
import logging
import sys
from threading import Thread
from Rule import *

#from InitializeRules import  *

class Sniffer(Thread):
    def __init__(self, ruleList):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList

    def stop(self):
        self.stopped = True
    def stopfilter(self, x):
        return self.stopped

    def match(self, pkt):
        #print("Checking for any packets that match a rule...")
        """To prevent false positives we need to ensure that all parts of the packet match one of our rules"""
        """This is where checking the correct parameters is critical"""
        pkt.summary()


    def inPkt(self, pkt):
        for rule in self.ruleList:
            #Check all rules
            # print "checking rule"
            matched = self.match(pkt)
            if(matched):
                logMessage = rule.getMatchedMessage(pkt)
                logging.warning(logMessage)
                print(rule.getMatchedPrintMessage(pkt))
    def run(self):
        print("Sniffing has started")
        sniff(filter="", prn=self.inPkt, store=0, stop_filter=self.stopfilter)



