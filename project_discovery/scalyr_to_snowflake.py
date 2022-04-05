#!/usr/bin/env python3
"""

* Script to query scalyr logs and save results to Snowflake

requirements:

- Snowflake connection configutations
- Scalyr access token
- Snowflake connector for python

reference:https://www.lacework.com/blog/the-oast-with-the-most/

authors:
christopher.hall@lacework.net
kristinn.gudjonsson@lacework.net

"""
try:
    import snowflake.connector
except:
    pass
import datetime
import json
import os
import logging
import socket
import re

import pandas as pd
import http.client as httplib
import base64
import time
import json


#####USER CONFIGURATIONS######################################################################################################
##############################################################################################################################
##############################################################################################################################

#your Snowflake table name
snowflake_table_name = 'scalyr_sftest'

#start and end time for scalyr query
date_ranges = [["2022-03-01T00:00:00.000000","2022-03-02T00:00:00.000000"]]

#your scalyr query filter
SCALYR_QUERY = """"remote_addr" and (".interact.sh" or ".oast.pro" or ".oast.live" or ".oast.site"or ".oast.online" or ".oast.fun" or ".oast.me")"""
print('**query:',SCALYR_QUERY)

#Snowflake connection configs
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

#Scaylr access token
token = '(your scalyr access token here)'

##############################################################################################################################
##############################################################################################################################


create_table = """create table """+snowflake_table_name+"""(
created_time timestamp_ltz(9),
filter varchar(4096),
raw_msg VARIANT);"""

create_temp_table = """create table """+snowflake_table_name+"""_temp(
created_time timestamp_ltz(9),
filter varchar(4096),
raw_msg VARIANT);"""



created_ = 0
try:
    cur.execute(create_table)
except:
    created_ = 1
    pass

try:
    cur.execute(create_temp_table)
except:
    created_ = 1
    pass


if created_ == 1:

    print('* Created main and temporary table')
    print('  - main table:',snowflake_table_name)
    print('  - temp table:',snowflake_table_name+'_temp')

count=20000
priority = 'low'
mode = 'tail'
LOOKBACK = '24h'
COLUMNS = "app,raw_timestamp,serverIP,nginxFilters"

amount_to_insert = 100




logger = logging.getLogger("logger.scalyr")



class Scalyr:
    """
    Simple class to connect to a scalyr app.
    """

    # The default server to connect to.
    DEFAULT_SERVER = 'www.scalyr.com'

    # The maximum number of records returned back from an API call for
    # a log query.
    QUERY_MAX_COUNT = 5000

    # Arbitrary limit we put on number of records
    QUERY_MAX = 20000

    def __init__(self, server=''):
        self._conn = None

        if server:
            if server.startswith('https:'):
                _, _, self._server = server.partition('https://')
                self._use_ssl = True
            elif server.startswith('http://'):
                _, _, self._server = server.partition('http://')
                self._use_ssl = False
            else:
                self._use_ssl = True
                self._server = server
        else:
            self._server = self.DEFAULT_SERVER
            self._use_ssl = True

        self._headers = {
            'Content-type': 'application/json'
        }
        self._token = ''

    def _connect(self):
        """
        Connects to a HTTPS server.
        """
        if self._use_ssl:
            self._conn = httplib.HTTPSConnection(self._server)
        else:
            self._conn = httplib.HTTPConnection(self._server)

    @property
    def quota(self):
        """
        Returns a DataFrame with the latest quota information.

        :return: A pandas DataFrame.
        """
        return self.query(
            query_filter="tag='audit' cpuUsage=*",
            columns=(
                'startTime,cpuUsage,cpuUsageCapacity,cpuUsageLimit,'
                'cpuUsageRefillRate,maxCount,permission,queryType,'
                'filter,ip,user,status'),
            count=100,
            mode='tail',
            priority='low'
        )

    def auth(self):
           
        self._token = token.strip()


    def post(self, uri, parameters):
        """
        Returns a JSON dict from a POST request to a URI of the Scalyr app.

        :param str uri: The URI of the Scalyr app to send the request to.
        :param dict parameters: A dict with all the parameters to the POST
            request.
        :raises ValueError: If not authenticated, or if the response did not
            return back a 200 status code.
        :return: Returns a JSON dict with the results of the HTTP POST request.
        """


        persistconn = 0
        seconds_to_wait = 15
        iteration = 1

        while persistconn == 0:
            if not self._token:
                raise ValueError('Need to authenticate first.')
            print('\n')
            print('* querying scalyr..')

            # Resetting the HTTP connection for every request, otherwise queries
            # will start to fail.
            self._connect()

            parameters['token'] = self._token
            parameters_json = json.dumps(parameters)

            self._conn.request('POST', uri, parameters_json, self._headers)
            response = self._conn.getresponse()
            #print(response.status)

            if response.status != 200:
                iteration += 1
                if response.status == 429:
                    seconds_to_wait += 10
                    print('rate limited.. waiting for',seconds_to_wait,'seconds and trying again..')

                    time.sleep(seconds_to_wait)
                    continue


                reason = response.reason
                if not reason:
                    reason = (
                        'Unkown reason, look for status code on Scalyr API '
                        'documentation site.')

                raise ValueError(
                    'Unable to execute query [{0:d}] - {1:s}'.format(
                        response.status, reason))

            if response.status == 200:
                iteration += 1
                persistconn = 1
                               


            body = response.read()
            try:
                body = body.decode('utf8')
            except UnicodeDecodeError:
                logger.error('Unable to decode request response', exc_info=True)

        return json.loads(body)

    def query(  # noqa: C901
        
            self, query_filter, lookback = '',count=10, mode='head',
            columns='message', priority='low',start='',end=''):
        """
        Query scalyr and return back a DataFrame with the results.

        :param str query_filter: The query filter to send to the Scalyr app.
        :param str start: The start date of the filter query, if not provided
            this defaults to two days ago.
        :param str end: The end date of the filter query, if not provided
            this defaults to the current time.
        :param int count: The number of record to turn back, has to be higher
            than zero, defaults to 10 with a maximum of 20k.
        :param str mode: The default behavior whether you get back the
            oldest (head) or newest matches (tail) if the query surpasses
            the maximum number of requests served. Defaults to head.
        :param str columns: A comma separated list of all the columns to
            return from Scalyr. The message column is included by default.
        :param str priority: The priority of the request, the options
            are low and high, defaults to low.
        :return: A pandas DataFrame with the results.

        current_time = datetime.datetime.utcnow()
        print('debug current time ',current_time)
        """
        
        """

        start = datetime.datetime.strptime(start,"%Y-%m-%d")
        start = start.isoformat()


        end = datetime.datetime.strptime(end,"%Y-%m-%d")
        end = end.isoformat()
        
        if not start:
            two_days = current_time - datetime.timedelta(days=2)
            start = two_days.isoformat()
        """

        if not end:
            end = current_time.isoformat()
        
        

        if 'message' not in columns:
            columns_list = columns.split(',')
            columns_list.append('message')
            columns = ','.join(columns_list)

        if count >= self.QUERY_MAX:
            page = True
            total_count = self.QUERY_MAX
            count = 1000
        elif count >= self.QUERY_MAX_COUNT:
            page = True
            total_count = count
            count = 1000
        else:
            page = False
            total_count = count


        parameters = {
            'queryType': 'log',
            'filter': query_filter,
            'startTime': start,
            'endTime':end,
            'maxCount': count,
            'pageMode': mode,
            'columns': columns,
            'priority': priority,
        }


        lines = []
        while True:
            try:
                response = self.post('/api/query', parameters)

            except ValueError as exc:
                raise
                logger.error(
                    'Unable to complete query - {0} ({1:d} records '
                    'fetched)'.format(exc, len(lines)))
                break

            matches = response.get('matches', [])

            print('total matches ',len(matches))
            
            for match in matches:
                line = match.get('attributes')
                line['message'] = match.get('message')
                lines.append(line)

            if not page:
                break

            if len(lines) >= total_count:
                break

            cont_token = response.get('continuationToken', '')
            if not cont_token:
                break

            parameters['continuationToken'] = cont_token

        return pd.DataFrame(lines)

    def __enter__(self):
        """
        Support the with statement in python.
        """
        self.auth()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Support the with statement in python.
        """
        pass



def query_scalyr(
        query_filter, start='', end='', count=1000, mode='tail',
        columns='message', priority='low', ctx=None):
    """
    Query scalyr and return back a DataFrame with the results.

    :param str query_filter: The query filter to send to the Scalyr app.
    :param str start: The start date of the filter query, if not provided
        this defaults to two days ago.
    :param str end: The end date of the filter query, if not provided
        this defaults to the current time.
    :param int count: The number of record to turn back, has to be higher
        than zero, defaults to 10 with a maximum of 20k.
    :param str mode: The default behavior whether you get back the
        oldest (head) or newest matches (tail) if the query surpasses
        the maximum number of requests served. Defaults to head.
    :param str columns: A comma separated list of all the columns to
        return from Scalyr. The message column is included by default.
    :param str priority: The priority of the request, the options
        are low and high, defaults to low.
    :param obj ctx: The context object.
    :return: A pandas DataFrame with the results.
    """


    with Scalyr() as scalyr_client:
        return scalyr_client.query(
            query_filter=query_filter, start=start, end=end,
            count=count, mode=mode, columns=columns, priority=priority)



def get_scalyr_client(ctx=None):
    """
    Returns a Scalyr client.

    :param obj ctx: The context object.
    :return: A Scalyr object.
    """
    client = Scalyr()
    client.auth()

    if ctx:
        ctx.add('scalyr_client', client)

    return client


with Scalyr() as scalyr_client:

    scalyr_client.auth()


    for r in date_ranges:


        START_TIME = r[0]
        END_TIME = r[1]



        totalinserted = 0

        temp_insert = []

        



        time.sleep(5)

        scalyr_df = scalyr_client.query(
                query_filter=SCALYR_QUERY, lookback=LOOKBACK,
                count=count, mode=mode, columns=COLUMNS, priority=priority,start=START_TIME,end=END_TIME)



        for index,row in scalyr_df.iterrows():



            data = row['message']
            app = row['app']
            serverIP = row['serverIP']
            created_time = str(row['raw_timestamp'])

            try:
                jsondata = json.loads(data)
            except:
                print('JSON ERROR!!')
                print(data)
                continue

            
            app_str = str(app)
            serverIP_str = str(serverIP)

            rowdata_temp = str((created_time,SCALYR_QUERY,data))

            temp_insert.append(rowdata_temp)


            if len(temp_insert) >= 20000:
                print('** Hit maximum result set. Try adjusting your query or timeframe for full visibility')
                print(START_TIME,END_TIME)

            if len(temp_insert) > amount_to_insert:

                totalinserted += len(temp_insert)

                insert_joined = ','.join(temp_insert)

                insert = """insert into """+snowflake_table_name+"""_temp
                            select column1 as created_time,
                            column2 as filter,
                            parse_json(column3) as raw_msg
                            from values """+insert_joined+""";"""
                try:
                    cur.execute(insert)
                    temp_insert = []
                except:
                    print(insert)
                    raise

        if len(temp_insert) != 0:


            totalinserted += len(temp_insert)

            insert_joined = ','.join(temp_insert)

            insert = """insert into """+snowflake_table_name+"""_temp
                        select column1 as created_time,
                        column2 as filter,
                        parse_json(column3) as raw_msg
                        from values """+insert_joined+""";"""

            try:
                cur.execute(insert)


                temp_insert = []
            except:
                print(insert)
                raise

        print('\n')
        print('* Records inserted ',totalinserted)
            


print('* merging with main table (for deduplication)')

merge = """merge into """+snowflake_table_name+"""
using """+snowflake_table_name+"""_temp on
 ("""+snowflake_table_name+""".raw_msg = """+snowflake_table_name+"""_temp.raw_msg AND
  """+snowflake_table_name+""".created_time = """+snowflake_table_name+"""_temp.created_time AND
  """+snowflake_table_name+""".filter = """+snowflake_table_name+"""_temp.filter) 
when not matched 
then insert (filter,created_time,raw_msg) values 

("""+snowflake_table_name+"""_temp.filter,
"""+snowflake_table_name+"""_temp.created_time,
"""+snowflake_table_name+"""_temp.raw_msg);"""

cur.execute(merge)



print('* truncating temp table..')
print('\n')
print('* Done!')

cur.execute("truncate table """+snowflake_table_name+"""_temp""")






cur.close()
conn.close()

