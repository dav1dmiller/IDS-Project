import RuleFileReader
from Sniffer import *

filename = "test.txt"


def main(filename):
    print("===========================")
    print("Simple IDS Project")
    print("CS 497-8 Computer Security")
    print("By: David and Daniel")
    print("===========================")
    print("IDS starting...")

    #now = datetime.now()
    #logging.basicConfig(filename="IDS_project " + str(now) + '.log', level=logging.INFO)

    global ruleList
    rulelist, errorCount = RuleFileReader.read(filename)
    if (errorCount == 0):
        print("All items in file have been read and assigned values")
    else:
        print("Error Count: " + errorCount)
    sniffer = Sniffer(rulelist)
    sniffer.run()

main(filename)
