
# -----------------------------------------------------------
# Companion script for Lacework Labs blog - "Threat Research with Snowflake & VirusTotal"
#   reference:https://www.lacework.com/blog/threat-research-with-snowflake-virustotal/
#
#
# Released under GNU Public License (GPL)
# email christopher.hall@lacework.net
# -----------------------------------------------------------

try:
    import snowflake.connector
except:
    pass
import datetime
import time
import re
from difflib import *
import json

differential = 0#1 = differential update, 0 = full update

insert_amount= 500#amount of records to load into Snowflake at once

stem = "INSERT into vt_clustering values "

now = datetime.datetime.now()
now_str = now.strftime("%Y-%m-%d %H:%M:%S")

generics = ['trojan','generic','linux','gen']


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
cur2 = conn.cursor()


classified_files = set()

query = "select distinct sha256 from vt_clustering"

cur.execute(query)

for row in cur:
    
    sha256 = row[0]
    
    classified_files.add(sha256)


if differential == 1:
    
    query = "select max(etl_time) from vt_clustering"
    
    cur.execute(query)
    
    for row in cur:
        if row[0] is None:
            print('No cluster names in database, changing to full udpate')
            differential = 0
        cluster_etl = str(row[0])
        break
    print('clustering specimens added after',cluster_etl)



print('already classified ',len(classified_files))

def getnamerankings(names):

    substring_counts = {}

    for i in range(0, len(names)):
        for j in range(i+1,len(names)):
            string1 = names[i]
            string2 = names[j]
            match = SequenceMatcher(None, string1, string2).find_longest_match(0, len(string1), 0, len(string2))
            matching_substring=string1[match.a:match.a+match.size]
            if(matching_substring not in substring_counts):
                substring_counts[matching_substring]=1
            else:
                substring_counts[matching_substring]+=1
    substring_ranks = []
    for k,v in substring_counts.items():
        substring_ranks.append([v,k])
    substring_ranks   = reversed(sorted(substring_ranks))

    return substring_ranks


def classify(normalized_names):

    filtered_names = []    

    toprintcount2 = 0

    for i in normalized_names:

        if i[1] not in generics and len(i[1])>3:
            filtered_names.append(i)

    return filtered_names[0][1]
    



def getnames(avnames,totalavnames):

    names = []

    try:
        for k,v in avnames.items():
            result = str(v['result'])
            if result != 'None' and result != 'null':
                totalavnames.add(result)
                resultnorm = re.split(r'[`\-=~!@#$%^&*()_+\[\]{};\'\\:"|<,./<>?1234567890]', result)
                resultnorm = ''.join(resultnorm)
                names.append(resultnorm.lower())

    except:
        raise

    return names,totalavnames


name_clusters = {}

totalavnames = set()

data_ = {}
uri_to_hosts = {}
payload_to_hosts = {}

already_processed = 0

all_rows = []

try:

    if differential == 1:
        query = "select sha256,PROPS:data.attributes.last_analysis_results from VT_COLLECTION_RELATIONS where etl_time >= '"+cluster_etl+"';"
    else:
        query = "select sha256,PROPS:data.attributes.last_analysis_results from VT_COLLECTION_RELATIONS;"
        
    
    cur.execute(query)

    for row in cur:

        sha256 = row[0]

        if sha256 in classified_files:
            already_processed += 1
            continue

        try:

            avnames =  json.loads(row[1])
        except:
            print('JSON LOADS ERROR..')
            print(row)
            raise
        
        names_result = getnames(avnames,totalavnames)

        names = names_result[0]
        totalavnames = names_result[1]
        

        normalized_names = getnamerankings(names)

        
        toprintcount = 0


        try:
            classification = classify(normalized_names)

        except:


            if len(names) != 0:
                classification_ = names[0]
                classification = 'low_detection('+classification_+')'

                
            else:
                
                classification = 'undetected'


        data_ = (sha256,classification,now_str)

        all_rows.append(str(data_))

        if len(all_rows) >= insert_amount:

            print('bulk insert ',len(all_rows))

            insert_data_joined = ','.join(all_rows)

            insert_statement = stem+insert_data_joined+';'

            cur2.execute(insert_statement)
            all_rows = []



        
except:
    print('exiting')
    
    cur.close()
    conn.close()
    raise



if len(all_rows) != 0:
    print('inserting remainder..')
    
    print('bulk insert ',len(all_rows))

    insert_data_joined = ','.join(all_rows)

    insert_statement = stem+insert_data_joined+';'

    cur2.execute(insert_statement)


print('done!')


cur.close()
conn.close()




