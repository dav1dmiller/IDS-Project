
from scapy.all import *

from sniffer import *
import datetime
import RuleFileReader





def main():
    print("Debug test")
    #Read rules from rule file
    print("Simple NIDS")
    print("By: David and Daniel")

    filename = open("test.txt", "w+")

    sniffer = Sniffer()
    sniffer.run(filename)


main(filename)

