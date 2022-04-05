#!/usr/bin/env python3
"""
* Parses Project Discovery nuclei templates
& inserts into Snowflake table


requirements:

- Snowflake connection configutations
- local Nuclei templates repo:
    - https://github.com/projectdiscovery/nuclei-templates

reference:https://www.lacework.com/blog/the-oast-with-the-most/

author:christopher.hall@lacework.net



"""
import yaml

import os
import ast
try:
    import snowflake.connector
except:
    pass
import json


#####USER CONFIGURATIONS######################################################################################################
##############################################################################################################################
##############################################################################################################################

rootdir = "nuclei-templates-master"#directory containing repo

snowflake_table = 'nuclei_templates'


#your Snowflake connection config
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
##############################################################################################################################
##############################################################################################################################

create_table = """create or replace table """+snowflake_table+"""(
PATH varchar(4096),
YAML VARIANT );"""


cur.execute(create_table)

print('created table '+snowflake_table)

amount_to_insert = 100


debugcount = 0

temp_insert = []

totalinserted = 0
for folder, subs, files in os.walk(rootdir):

    for filename in files:


        filepath = os.path.join(folder, filename)
        if filename.endswith('.yaml'):

            try:
                yamlfile = open(filepath,'r')
                data = yamlfile.read()                


                test = yaml.safe_load(data)

                id_ = test['id']
                name_ = test['info']['name']


                try:

                    test = json.dumps(test)
                    test = str(test)

                    rowdata_temp = str((filepath,test))
                    
                    temp_insert.append(rowdata_temp)

                except:
                    raise

                if len(temp_insert) == amount_to_insert:
                    print('inserting ',len(temp_insert))


                    totalinserted += len(temp_insert)

                    insert_joined = ','.join(temp_insert)

                    insert = """insert into """+snowflake_table+"""
                        select column1 as path,
                        parse_json(column2) as yaml
                        from values """+insert_joined+""";"""
                    try:
                        cur.execute(insert)


                        temp_insert = []
                    except:
                        print(insert)
                        raise

                
            except:
                raise



if len(temp_insert) > 0:
    print('inserting REMAINDER ',len(temp_insert))

    totalinserted += len(temp_insert)

    insert_joined = ','.join(temp_insert)

    insert = """insert into """+snowflake_table+"""
        select column1 as path,
        parse_json(column2) as yaml
        from values """+insert_joined+""";"""
    try:
        cur.execute(insert)

    except:
        print(insert)
        raise

print('total Yaml files inserted in Snowflake',totalinserted)



cur.close()
conn.close()
