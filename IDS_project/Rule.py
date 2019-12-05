#Use this file to initialize the rules that we write
from scapy.all import *
from RuleFileReader import *
from IDS_project.RuleFileReader import rulelist

class Rule:
    """Need to make a rule out of a string. This is necessary because we have to be able to compare incoming packets to a rule not a string"""
    def __init__(self, str):
        print("Making the new rule..")
        self.string = str
        #strip extra white spaces
        str = str.strip()
        #split on the , for the different values to store
        token = str.split(',')
        #Duration
        try:
            duration=token[0]
            #print(duration)
        except:
            raise ValueError("Invalid rule: incorrect value for duration " + token[0])
        #protocol_type
        try:
            protocol_type=token[1]
            print(protocol_type)
        except:
            raise ValueError("Invalid rule: incorrect value for protocol_type " + token[1])
        #Service
        try:
            service=token[2]
            #print(service)
        except:
            raise ValueError("Invalid rule: incorrect value for service " + token[2])
        #Flag
        try:
            flag=token[3]
            #print(flag)
        except:
            raise ValueError("Invalid rule: incorrect value for flag " + token[3])
        #src_bytes
        try:
            src_bytes=token[4]
            #print(src_bytes)
        except:
            raise ValueError("Invalid rule: incorrect value for src_bytes " + token[4])
        # dst_bytes
        try:
            dst_bytes = token[5]
            #print(dst_bytes)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_bytes " + token[5])
        #land
        try:
            land = token[6]
            #print(land)
        except:
            raise ValueError("Invalid rule: incorrect value for land " + token[6])
        #wrong_fragment
        try:
            wrong_fragment = token[7]
            #print(wrong_fragment)
        except:
            raise ValueError("Invalid rule: incorrect value for wrong_fragment " + token[7])
        #urgent
        try:
            urgent = token[8]
            #print(urgent)
        except:
            raise ValueError("Invalid rule: incorrect value for urgent " + token[8])
        #hot
        try:
            hot = token[9]
            #print(hot)
        except:
            raise ValueError("Invalid rule: incorrect value for hot " + token[9])
        #num_failed_logins
        try:
            num_failed_logins = token[10]
            #print(num_failed_logins)
        except:
            raise ValueError("Invalid rule: incorrect value for num_failed_logins " + token[10])
        #logged_in
        try:
            logged_in = token[11]
            #print(logged_in)
        except:
            raise ValueError("Invalid rule: incorrect value for logged_in " + token[11])
        #num_compromised
        try:
            num_compromised = token[12]
            #print(num_compromised)
        except:
            raise ValueError("Invalid rule: incorrect value for num_compromised " + token[12])
        #root_shell
        try:
            root_shell = token[13]
            #print(root_shell)
        except:
            raise ValueError("Invalid rule: incorrect value for root_shell " + token[13])
        #su_attempted
        try:
            su_attempted = token[14]
            #print(su_attempted)
        except:
            raise ValueError("Invalid rule: incorrect value for su_attempted " + token[14])
        #num_root
        try:
            num_root = token[15]
            #print(num_root)
        except:
            raise ValueError("Invalid rule: incorrect value for num_root " + token[15])
        #num_file_creations
        try:
            num_file_creations = token[16]
            #print(num_root)
        except:
            raise ValueError("Invalid rule: incorrect value for num_file_creations " + token[16])
        #num_shells
        try:
            num_shells = token[17]
            #print(num_shells)
        except:
            raise ValueError("Invalid rule: incorrect value for num_shells " + token[17])
        #num_access_files
        try:
            num_access_files = token[18]
            #print(num_access_files)
        except:
            raise ValueError("Invalid rule: incorrect value for num_access_files " + token[18])
        #num_outbound_cmds
        try:
            num_outbound_cmds = token[19]
            #print(num_outbound_cmds)
        except:
            raise ValueError("Invalid rule: incorrect value for num_outbound_cmds " + token[19])
        #is_hot_login
        try:
            is_hot_login = token[20]
            #print(is_hot_login)
        except:
            raise ValueError("Invalid rule: incorrect value for is_hot_login " + token[20])
        #is_guest_login
        try:
            is_guest_login = token[21]
            #print(is_guest_login)
        except:
            raise ValueError("Invalid rule: incorrect value for is_guest_login " + token[21])
        #count
        try:
            count = token[22]
            #print(count)
        except:
            raise ValueError("Invalid rule: incorrect value for count " + token[22])
        #srv_count
        try:
            srv_count = token[23]
            #print(srv_count)
        except:
            raise ValueError("Invalid rule: incorrect value for srv_count " + token[23])
        #serror_rate
        try:
            serror_rate = token[24]
            #print(serror_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for serror_rate " + token[24])
        #srv_serror_rate
        try:
            srv_serror_rate = token[25]
            #print(srv_serror_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for srv_serror_rate " + token[25])
        #rerror_rate
        try:
            rerror_rate = token[26]
            #print(rerror_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for rerror_rate " + token[26])
        #srv_rerror_rate
        try:
            srv_rerror_rate = token[27]
            #print(srv_rerror_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for srv_rerror_rate " + token[27])
        #same_srv_rate
        try:
            same_srv_rate = token[28]
            #print(same_srv_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for same_srv_rate " + token[28])
        #diff_srv_rate
        try:
            diff_srv_rate = token[29]
            #print(diff_srv_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for diff_srv_rate " + token[29])
        #srv_diff_host_rate
        try:
            srv_diff_host_rate = token[30]
            #print(srv_diff_host_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for srv_diff_host_rate " + token[30])
        #dst_host_count
        try:
            dst_host_count = token[31]
            #print(dst_host_count)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_count " + token[31])
        #dst_host_srv_count
        try:
            dst_host_srv_count = token[32]
            #print(dst_host_srv_count)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_srv_count " + token[32])
        #dst_host_same_srv_rate
        try:
            dst_host_same_srv_rate = token[34]
            #print(dst_host_same_srv_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_same_srv_rate " + token[33])
        #dst_host_diff_srv_rate
        try:
            dst_host_diff_srv_rate = token[34]
            #print(dst_host_diff_srv_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_diff_srv_rate " + token[34])
        #dst_host_same_src_port_rate
        try:
            dst_host_same_src_port_rate = token[35]
            #print(dst_host_same_src_port_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_same_src_port_rate " + token[35])
        #dst_host_srv_diff_host_rate
        try:
            dst_host_srv_diff_host_rate = token[36]
            #print(dst_host_srv_diff_host_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_srv_diff_host_rate " + token[36])
        #dst_host_serror_rate
        try:
            dst_host_serror_rate = token[37]
            #print(dst_host_serror_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_serror_rate " + token[37])
        #dst_host_srv_serror_rate
        try:
            dst_host_srv_serror_rate = token[38]
            #print(dst_host_srv_serror_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_srv_serror_rate " + token[38])
        #dst_host_rerror_rate
        try:
            dst_host_rerror_rate = token[39]
            #print(dst_host_rerror_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_rerror_rate " + token[39])
        #dst_host_srv_rerror_rate
        try:
            dst_host_srv_rerror_rate = token[40]
            #print(dst_host_srv_rerror_rate)
        except:
            raise ValueError("Invalid rule: incorrect value for dst_host_srv_rerror_rate " + token[40])
        #attack_type
        try:
            attack_type = token[41]
            #print(attack_type)
        except:
            raise ValueError("Invalid rule: incorrect value for attack_type " + token[41])
        #final_number
        try:
            final_number = token[42]
            #print(final_number)
        except:
            raise ValueError("Invalid rule: incorrect value for final_number " + token[42])


