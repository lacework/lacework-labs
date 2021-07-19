
# -----------------------------------------------------------
# Companion script for Lacework Labs blog - "Threat Research with Snowflake & VirusTotal"
#   reference:https://www.lacework.com/blog/
#
#
# Released under GNU Public License (GPL)
# email christopher.hall@lacework.net
# -----------------------------------------------------------


import re,sys
import json
import requests
import time
import os
import csv
from datetime import date
try:
    import snowflake.connector
except:
    pass
import datetime


insertamount = 100#amount of records to insert into Snowflake at one time

all_rows = []

#Snowflake connection configurations
conn = snowflake.connector.connect(
    user='',
    password='',
    account='',
    warehouse='',
    database='',
    schema='',
    role=''
    )

cur = conn.cursor()


stem = "INSERT into vt_collection_relations select column1 as SHA256,column2 as START_TIME,column3 as END_TIME,column4 as ETL_TIME, parse_json(column5) as PROPS from values "

api_key = 'your VirusTotal API key here!'


qs = []

try:
    with open('collection_requirements.txt','r') as infile:
        for line in infile:
            req = line.strip()
            if line.startswith('#') or len(line) == 1:
                continue
            
            qs.append(req)
except:

    print('no collection requirements!(collection_requirements.txt)')
    exit()



today = str(date.today())


already_processed = []



hashes = {}

hash_search = {}

hashes_unique = []


def VT_query(query,offset):
    results = []
    result_master = []
    try:
        int(offset)

        params = {'apikey': api_key, 'query': query}
    except:
        params = {'apikey': api_key, 'query': query, 'offset':offset}
      
    response = requests.get('http://www.virustotal.com/vtapi/v2/file/search', params=params, verify=False)
    response_result = str(response)
    if response_result == '<Response [204]>':
        return '204'
    if not response_result == '<Response [204]>':
        try:
            json_response = response.json()
            test = json_response["hashes"]
            for hashes in test:
                results.append(hashes)
            try:
                offset = json_response["offset"]
                result_master.append(results)
                result_master.append(offset)
                result_master.append('offset_check')
                return result_master
            except:
                return results
        except:
            pass



all_hashes = set()

print('querying hashes from VT...')

result_page_counter = 0
for q in qs:
    print('      VT query:',q)
    offset = 1
    results = VT_query(q,offset)

    while offset == 1:
        if results is None:
            break

        if len(results) == 3 and results[2] == 'offset_check':
            result_page_counter += 1
            print('      iterating VT results..',result_page_counter)
            hashes = results[0]
            offset = results[1]
            results = VT_query(q,offset)

            offset = 1
            for samp in hashes:                

                all_hashes.add(samp)
        else:

            offset = 0
            hashes = results[0]
            hashes = results
            if len(hashes[0]) == 1:
                all_hashes.add(hashes)

        #offset = 0



print('total samples to process..',len(all_hashes))

    
hashes_unique = all_hashes


def query_VT_behaviorv3(sha256):

        url = 'https://www.virustotal.com/api/v3/files/'+sha256+'?relationships=embedded_urls,itw_urls,itw_ips,contacted_ips,contacted_domains'


        proxies=None
        timeout=None

        response = requests.get(url,
                                headers={'x-apikey': api_key,
                                         'Accept': 'application/json'},
                                proxies=proxies,
                                timeout=timeout)
        if response.status_code != 200:
            print(response)
            raise


        return response.content


already_proc = []



cur.execute("select distinct SHA256 from vt_collection_relations")
for row in cur:
    sha256 = row[0]
    already_proc.append(sha256)

        
totalskipped = 0

hashes_to_proc = []


for sha256 in hashes_unique:


    if sha256 in already_proc:
        totalskipped += 1
        continue
    hashes_to_proc.append(sha256)

print('skippped',totalskipped)
print('processing',len(hashes_to_proc))
print('Querying VT data and writing to SF ....')


for sha256 in hashes_to_proc:

    try:
        json_result = query_VT_behaviorv3(sha256)
    except:
        print('exception on API query..')
        continue


    #######################################

    tempfile = str(sha256)+'.txt'

    with open(tempfile,'wb') as f_:
        f_.write(json_result)

    f_.close()    

    datatest = open(tempfile,'r')
    
    datatestraw = open(tempfile,'r')

    rawjsondata = str(datatestraw.read())
       
    data_temp = json.loads(datatest.read())

    os.remove(tempfile)#comment me to retain local file..

    #######################################    


    try:

        attrib = data_temp['data']['attributes']
        first_seen = attrib['first_submission_date']
        last_seen = attrib['last_analysis_date']
        file_hash = attrib['sha256']


        if file_hash in already_proc:

            continue

        
        fs_ = str(datetime.datetime.fromtimestamp(first_seen))
        ls_ = str(datetime.datetime.fromtimestamp(last_seen))

        now = datetime.datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")

        data = (file_hash,fs_,ls_,now_str,rawjsondata)
        all_rows.append(str(data))       


    
        if len(all_rows) >= insertamount:


            insert_data_joined = ','.join(all_rows)

            insert_statement = stem+insert_data_joined+';'

            print('  inserting ',len(all_rows),'rows!')

            temp_insert = []

            cur.execute(insert_statement)
            all_rows = []



    except Exception as ex:
        raise


   

if len(all_rows) > 1:


    insert_data_joined = ','.join(all_rows)

    insert_statement = stem+insert_data_joined+';'
    print(' inserting remainder - ',len(all_rows),'rows')

    temp_insert = []

    cur.execute(insert_statement)
    all_rows = []



cur.close()
conn.close()


    


