import csv
class firewall:
    list_of_rules = [] # python list to store rule tuples
    def __init__(self,path):
        reader = csv.DictReader(open(path, 'rb'))   # read csv file
        for line in reader:
            if  '-' in line['IP'] and '-' in line['Port']: # ranges in both port and ip
                 holder_ip = line['IP'].split('-')          #split function to split range string at dash store strings in holder_ip
                 holder_port = line['Port'].split('-')
                 self.compute_ranges(holder_ip,holder_port,line) # helper method to insert rules in list

            elif '-' in line['IP'] and '-' not in line['Port']: # ranges in IP but not port
                holder_ip = line['IP'].split('-')
                self.compute_range_ip(holder_ip,line)   # helper method to insert rules in list

            elif '-' in line['Port'] and '-' not in line['IP']: # ranges in port but not IP
                holder_port = line['Port'].split('-')
                self.compute_range_port(holder_port,line)   # helper method to insert rules in list
            else: # no ranges
                tuple_to_append = {'Direction' : line['Direction'],'Protocol':line['Protocol'],'Port':line['Port'] ,'IP' :line['IP'].replace(".","")}
                self.list_of_rules.append(tuple_to_append)  # helper method to insert rules in list



    def accept(self,Direction,IP,Port,Protocol):
        newIP = str(IP).replace(".","") # replace . in ip with no space
        result = False
        for rule in self.list_of_rules: #O(n) run time search for matching rule
            if rule['Direction'] == Direction and rule['IP'] == newIP and rule['Port'] == str(Port) and rule['Protocol'] == Protocol:
                result = True
        print result


    def compute_ranges(self,holder_ip,holder_port,line): # called when ranges in both ip and port appear
        holder_ip = self.replace_ip(holder_ip) # helper to replace . in ip
        ip_range = int(holder_ip[1]) - int(holder_ip[0]) # compute range of ip
        port_range= int(holder_port[1]) - int(holder_port[0]) # compute range of port
        for i in range(0,ip_range+1): # all possible port and ip combinations in range
            for j in range(0,port_range+1):
                tuple_to_append = {'Direction' : line['Direction'],'Protocol':line['Protocol'],'Port': str(int(holder_port[0])+j),'IP' : str(int(holder_ip[0]) + i)}
                self.list_of_rules.append(tuple_to_append)

    def compute_range_ip(self,holder_ip,line):# called when ranges in ip but not port appear
        holder_ip = self.replace_ip(holder_ip)
        ip_range = int(holder_ip[1]) - int(holder_ip[0])
        for i in range(0, ip_range+1): # compute all possible combinations in ip address with single port
            tuple_to_append = {'Direction': line['Direction'], 'Protocol': line['Protocol'],'Port': line['Port'], 'IP': str(int(holder_ip[0]) + i)}
            self.list_of_rules.append(tuple_to_append)

    def compute_range_port(self, holder_port, line):# called when range in port but not ip
        ip_range = int(holder_port[1]) - int(holder_port[0])
        for j in range(0, ip_range +1): # compute all possible combinations in port
            tuple_to_append = {'Direction': line['Direction'], 'Protocol': line['Protocol'], 'Port': str(int(holder_port[0])+j) , 'IP':line['IP'].replace(".","")}
            self.list_of_rules.append(tuple_to_append)

    def replace_ip(self,holder_ip): # helper to replace . in ip address
        i = 0
        for each in holder_ip:
            holder_ip[i] = each.replace(".", "")
            i = i + 1
        return holder_ip


if __name__ == '__main__':
    f1 = firewall('rules.csv')
    f1.accept("outbound", "122.123.123.123", 82, 'tcp') # test for accept large value for ip
    f1.accept("outbound", "121.153.323.923", 82, 'tcp') # test for reject- does not match rules
    f1.accept("inbound","34.22.44.22",21,'udp')# test for reject- does not match rules
    f1.accept("outbound","1.1.2.3",45,'tcp')# test for accept - range in port no range in ip (port min)
    f1.accept("outbound","1.1.2.3",400,'tcp')# test for accept - range in port no range in ip (middle value)
    f1.accept("outbound","1.1.2.3",782,'tcp')# test for accept - range in port no range in ip (port max)
    f1.accept("inbound","127.1.1.0",699,'udp')# test for accept edge case(port min and ip min)
    f1.accept("inbound","127.1.2.2",1270,'udp')# test for accept rule in port and ip range
    f1.accept("inbound","128.4.3.1",1281,'udp')# test for accept edge case(port max and ip max)
    f1.accept("outbound","120.0.0.0",3728,'tcp')# test for accept edge case no port range and ip range
    f1.accept("outbound","121.1.2.1",3728,'tcp') #test for accept rule ip range
    f1.accept("outbound","121.4.2.1",3728,'tcp')#test for accept edge case(port max and ip max)





