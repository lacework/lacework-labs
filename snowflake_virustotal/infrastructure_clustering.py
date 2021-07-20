
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
import csv
import datetime
from datetime import timedelta
import time
import re

try:
    import geoip2.database
except:
    pass


####

lookback_amnt = 30#days to look back


now = datetime.datetime.now()

lookback = (now - timedelta(days = lookback_amnt)).strftime("%Y-%m-%d %H:%M:%S").split(' ')[0]



clusters = {}

        
now = datetime.datetime.now()
now_str = now.strftime("%Y-%m-%d %H:%M:%S").split(' ')[0]



csv_name = 'infrastructure_clustering_'+now_str+'.csv'

csv_path = csv_name



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

print('getting classifications from table..')

cur.execute("select * from vt_clustering")

for row in cur:
    sha256 = row[0]
    clustername = row[1]


    clusters[sha256] = clustername


hashes_to_cve = {}
hashes_to_uri = {}
hashes_to_payload = {}

cvequery = "with vt as (select *  from VT_COLLECTION_RELATIONS, lateral flatten(input => PROPS:data.attributes.tags) as value ) select value, sha256 fcount from vt where value like 'cve%';"
cur.execute(cvequery)

for row in cur:
    sha256 = row[1]
    cve = row[0]

    if sha256 in hashes_to_cve:
        hashes_to_cve[sha256].add(cve)
    else:
        hashes_to_cve[sha256] = set()
        hashes_to_cve[sha256].add(cve)       
    

try:

    asn_db = '/update/this/path/GeoLite2-ASN.mmdb'
    asn_reader = geoip2.database.Reader(asn_db)
except:
    print('WARNING - add path to GeoLite2-City.mmdb to enable ASN support')
    pass


try:
    cc_db = '/update/this/path/GeoLite2-City.mmdb'
    cc_reader = geoip2.database.Reader(cc_db)
except:
    print('WARNING - add path to GeoLite2-City.mmdb to enable geolocation support')
    pass

def getasn_cc(ip):
    try:
        response = asn_reader.asn(ip)
        asn = '"'+response.autonomous_system_organization+'"'
        asn_no = response.autonomous_system_number

    except:
        #raise
        asn = 'unknown'
        asn_no = 'unknown'

    cc_result = 1
    try:
        response_cc = cc_reader.city(ip)
        
    except:
        cc_result = 0

    cc_name = 'unknown'

    if cc_result == 1:
        try:
            iso_code = response_cc.country.iso_code
        except:
            iso_code = 'unk'
        
        try:
            cc_name = response_cc.country.name
        except:
            cc_name = 'unk'
                        
        
        try:
            city_name = response_cc.subdivisions.most_specific.name
        except:
            city_name = 'unk'



    asn_str = str(asn_no)+':'+asn

    return asn_str,cc_name





def getclusters(hashes_):

    cluster_counts = {}

    for hash_ in hashes_:
        try:
            clustername = clusters[hash_]
        except:
            clustername = 'unclassified'

        if clustername in cluster_counts:
            cluster_counts[clustername] += 1
        else:
            cluster_counts[clustername] = 1


    clusters_ordered = {k: v for k, v in sorted(cluster_counts.items(), key=lambda item: item[1],reverse=True)}

        
    return clusters_ordered



def getcves(hashes_):
    allcves = set()

    for hash_ in hashes_:
        try:
            hash_cves = hashes_to_cve[hash_]

            for cve in hash_cves:

                allcves.add(cve)
        except:
            continue

    allcves = list(allcves)
    return sorted(allcves)



def geturis(hashes_):
    alluris = set()

    for hash_ in hashes_:
        try:
            hash_uri = hashes_to_uri[hash_]

            for uri in hash_uri:

                alluris.add(uri)
        except:
            continue

    alluris = list(alluris)
    return sorted(alluris)


def getpayloads(hashes_):
    allpayloads = set()

    for hash_ in hashes_:
        try:
            hash_payload = hashes_to_payload[hash_]


            for payload in hash_payload:
                
                debugcheck = 1
                allpayloads.add(payload)
        except:
            continue

    allpayloads = list(allpayloads)
    return sorted(allpayloads)

header = ['domainip','firstseen','lastseen','asn','country','specimen_count','malware_clusters','cves','uri_clusters','name_clusters']

with open(csv_path, 'w') as csvfile:



    cwriter = csv.writer(csvfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)
    cwriter.writerow(header)

            

    data_ = {}
    host_starttimes = {}
    try:

        query = """with vt as (select *  from VT_COLLECTION_RELATIONS, lateral flatten(input => PROPS:data.relationships.itw_urls.data) as value ) select value:context_attributes.url, sha256,start_time from vt where start_time >= '"""+lookback+"""' order by sha256;"""

        cur.execute(query)

        for row in cur:

            itw_url = row[0]
            hash_ = row[1]
            start_time = row[2]



            try:
                temp = itw_url.split('/')
                uri = '/'.join(temp[3:-1])
                payload = temp[-1]


                if not uri == '':

                    if hash_ in hashes_to_uri:
                        hashes_to_uri[hash_].add(uri)
                    else:
                        hashes_to_uri[hash_] = set()
                        hashes_to_uri[hash_].add(uri)

                if not payload == '':

                    if hash_ in hashes_to_payload:
                        hashes_to_payload[hash_].add(payload)
                    else:
                        hashes_to_payload[hash_] = set()
                        hashes_to_payload[hash_].add(payload)
            except:
                pass

                    
            
            try:
                domain_ip = itw_url.split('//')[1].split('/')[0].split(':')[0]
                
            except:
                domain_ip = itw_url


            domain_ip = domain_ip.replace('"','')


            if domain_ip in host_starttimes:
                host_starttimes[domain_ip].add(start_time)
            if domain_ip not in host_starttimes:
                host_starttimes[domain_ip] = set()
                host_starttimes[domain_ip].add(start_time)                


            if domain_ip in data_:
                data_[domain_ip].add(hash_)
            if domain_ip not in data_:
                data_[domain_ip] = set()
                data_[domain_ip].add(hash_)                

        

        for domainip,sha256 in data_.items():
            
            
            filecount = len(sha256)


            asn_cc_data = getasn_cc(domainip)
            asn = asn_cc_data[0]
            country = asn_cc_data[1]


            clusterbreakdown = getclusters(sha256)

            cves = getcves(sha256)

            uris = geturis(sha256)
            payloads_ = getpayloads(sha256)


            firstseen = str(min(host_starttimes[domainip])).split(' ')[0]
            lastseen = str(max(host_starttimes[domainip])).split(' ')[0]
        
            cwriter.writerow([domainip,firstseen,lastseen,asn,country,filecount,clusterbreakdown,cves,uris,payloads_])
            


    except:
        print('exiting')
        
        cur.close()
        conn.close()
        raise


print('wrote clustering output to',csv_name)

            

cur.close()
conn.close()
