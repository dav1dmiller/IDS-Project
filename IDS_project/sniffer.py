from scapy.all import *
import logging
import sys

class Sniffer(Thread):
    def __init__(self, ruleList):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList

        def stop(self):
            self.stopped = True
        def stopfilter(self, x):
            return self.stopped

        def inPacket(self, pkt):
            """Directive for each received packet."""
            for rule in self.ruleList:
                # Check all rules
                # print "checking rule"
                matched = rule.match(pkt)
                if(matched):
                    logMessage = rule.getMatchedMessage(pkt)
                    logging.warning(logMessage)
                    print (rule.getMatchedPrintMessage(pkt))
    def run(self):
        print("Sniffing has started")
        sniff(filter="", prn=self.inPacket, store=0, stop_filter=self.stopfilter)



