
# -----------------------------------------------------------
# Processes downloaded Redis configuations from Shodan
#   - to be run after redis_collector.py
#
# Generates
#   - list of Redis rogue servers
#   - list of scanners
#   - first_seen & last_seen timestamps
#   - counts, port information & commands for each host
#
# Released under GNU Public License (GPL)
# email christopher.hall@lacework.net
# -----------------------------------------------------------


import ast
import json
import collections
import os
import json
import csv
from datetime import datetime
import ast
import re


indicator_csv = 'redis_threat_intel.csv'#output csv name

paths = ['/redis_configurations/']#path to Shodan Redis configurations



ip_times = {}
mhost_ports = {}

bogon =  '(^10\.)|(^0\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^127\.0\.0\.1)'


def search_is_IP(strg, search=re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", re.I).search):
    return bool(search(strg))




def extract_addr(str_,client_commands):


    
    master_host_data = {}
    master_host_data['master_host'] = 'na'
    master_host_data['master_port'] = 'na'

    temp1 = str_.split('\n')
    temp1 = ''.join(temp1)
    temp2 = temp1.split('\r')
    for t in temp2:
        
        if t.startswith('master_host'):
            master_host = t.lstrip('master_host:')
            master_host_data['master_host'] = master_host

        if t.startswith('master_port'):
            master_port = t.lstrip('master_port:')
            master_host_data['master_port'] = master_port

    ips = set()
    temp = str_.split("addr=")

    for items in temp:

        try:
            command = items.split(" cmd=")[1].split("\n")[0]
            if ' ' in command:
                command = command.split(' ')[0]
        except:
            command = 'na'
        temp2 = items.split(":")[0]
        if search_is_IP(temp2):

            ips.add(temp2)

        if command != 'na':
            if temp2 in client_commands:            
                client_commands[temp2].add(command)
            if temp2 not in client_commands:
                client_commands[temp2] = set()
                client_commands[temp2].add(command)
    
    return ips,master_host_data,client_commands



mhosts = {}
mports = {}

addrs = {}

client_commands = {}



########

for path in paths:
    allfiles = os.listdir(path)

    count  = 0
    print('processing..')

    redis_servers = [] 

    for jsonfile in allfiles:

        redisserver = jsonfile.split('.txt')[0]

        
        redis_servers.append(redisserver)
                
        
        filepath = path+jsonfile
        with open(filepath,'rb') as infile:

            count += 1


            for item in infile:

                item = item.strip()

         
                try:

                    data_ = ast.literal_eval(item)
                    redisdata = data_['data']
                    timestamp = data_['timestamp'].split('T')[0]

                    date_time_obj_fs = datetime.strptime(timestamp,'%Y-%m-%d')


                    extr_results = extract_addr(redisdata,client_commands)
                    
                    addresses = list(extr_results[0])
                    master_host_data = extr_results[1]

                    client_commands = extr_results[2]


                    for ip in addresses:

                
                        if(re.search(bogon, ip)):  
                            continue

                        if ip == redisserver:
                            continue
                        
                        if not search_is_IP(ip):
                            continue
                            
                        if ip in addrs:
                            
                            addrs[ip].add(redisserver)
                            
                        if ip not in addrs:
                            addrs[ip] = set()
                            addrs[ip].add(redisserver)
                            
                        if ip in ip_times:
                            ip_times[ip].add(date_time_obj_fs)


                        if ip not in ip_times:
                            ip_times[ip] = set()
                            ip_times[ip].add(date_time_obj_fs)


                    redis = data_['redis']


                    try:
                        replication = redis['replication']

                        master_host = replication['master_host']

                        master_port = replication['master_port']

                    except:

                        master_host = master_host_data['master_host']
                        master_port = master_host_data['master_port']

                        


                    if master_host != 'na':


                        
                        if(re.search(bogon, master_host)):  
                            continue
                    
                        if not search_is_IP(ip):
                            continue

                        if master_host in mhosts:
                            
                            mhosts[master_host].add(redisserver)
                            
                        if master_host not in mhosts:
                            mhosts[master_host] = set()
                            mhosts[master_host].add(redisserver)

                                
                        if master_host in mhost_ports :
                            
                            mhost_ports[master_host].add(master_port)

                        if master_host not in mhost_ports:
                            mhost_ports[master_host] = set()
                            mhost_ports[master_host].add(master_port)

                        if master_host in ip_times:
                            ip_times[master_host].add(date_time_obj_fs)


                        if master_host not in ip_times:
                            ip_times[master_host] = set()
                            ip_times[master_host].add(date_time_obj_fs)


                except Exception, e:

                    pass


mhosts_sort = []

over_amnt = 3


for k,v in mhosts.iteritems():

    mhosts_sort.append([len(v),k])

mhosts_sort = list(reversed(sorted(mhosts_sort)))
count = 0



addr_sort = []
for k,v in addrs.iteritems():
    #print k,v
    addr_sort.append([len(v),k])
    
addr_sort = list(reversed(sorted(addr_sort)))

count = 0


with open(indicator_csv, 'wb') as csvfile:
    indwriter = csv.writer(csvfile, delimiter=',',quotechar='"')
    header = ['host','type','connected_redis_instances','firstseen','lastseen','ports','commands']
    indwriter.writerow(header)


    for m in addr_sort:


        ip = m[1]
        redis_count = m[0]
        type_ = 'redis_scanner'

        if ip in redis_servers:
            type_ = 'redis_scanner+redis_host'
            #print ip,type_
            
        ports = '(high ports)'

        try:
            first_seen = min(ip_times[ip])
            last_seen = max(ip_times[ip])
        except:
            continue

        try:
            commands_ = list(client_commands[ip])
        except:
            commands_ = ''

        try:
            row = [ip,type_,redis_count,first_seen,last_seen,ports,commands_]
            indwriter.writerow(row)
            
        except:
            pass



    for m in mhosts_sort:

        type_ = 'possible_rogue_server'
        if m in redis_servers:
            type_ = 'possible_rogue_server+redis_host'

        ip = m[1]
        redis_count = m[0]
        try:
            first_seen = min(ip_times[ip])
            last_seen = max(ip_times[ip])
        except:
            continue
        try:

            ports = list(mhost_ports[ip])
        except:
            raise
        commands_ = ''
        try:
            row = [ip,type_,redis_count,first_seen,last_seen,ports,commands_]

            indwriter.writerow(row)
        except:

            pass


print('wrote results to ',indicator_csv)
