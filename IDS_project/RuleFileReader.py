from scapy.all import *
from Rule import*
rulelist = list()

def read(filename):
    """Read file with all the rule into IDS and return a list of rules"""
    with open(filename, 'r') as fp:
        cnt=1
        errorCount=0
        for line in fp:
            try:
                #print("Rule {} contents--> {}".format(cnt, line))
                cnt += 1
                rule = Rule(line)
                rulelist.append(rule)
                #print(rulelist.__len__())
            except ValueError as err:
                errorCount+=1
                print(err)

    return rulelist, errorCount
