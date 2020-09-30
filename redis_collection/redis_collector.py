
# -----------------------------------------------------------
# Downloads Redis server configuration data from Shodan
#   - requires API
#   - use before redis_processor.py
#
# Released under GNU Public License (GPL)
# email christopher.hall@lacework.net
# -----------------------------------------------------------

from shodan import Shodan
import os


path = '/output/'#download path

api_key = "aWAsQyIds3Z1DLuJvA4ePfM4RoWmWSxs"#(dummy key), replace with yours


api = Shodan(api_key)

limit = 500
counter = 0



search_ = """master_host port:"6379" OR port:"6379" "Connected Clients" """



for result in api.search_cursor(search_ ):

    """
    #uncomment to limit results
    counter += 1
    
    if counter >= limit:
        break

    """


    ip_str = result['ip_str']
    
    print(ip_str)

    
    filepath = path+ip_str+'.txt'

    print('writing ',filepath)
    
    with open(filepath,'wb') as f:
        f.write(str(result))










        
