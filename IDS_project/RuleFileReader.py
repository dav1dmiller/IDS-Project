from scapy.all import *


def read(filename):
    list = list()
    with open(filename, 'r') as f:
        errorCount=0
        for line in f:
            try:
                rule=Rule(line)
                list.append(rule)
            except ValueError as err:
                errorCount+=1
                print(err)

    return errorCount
