"""
This module is intended to be used with projets or tools 
which tends to use a packaged or built in python and cannot 
directly install dependencies. 

This module is supposed to run in Python 2

The saram_py2_new_section function will create a new section 
for an entry.
"""
import json
import urllib2
from os.path import expanduser


try:
    conf_file_path = expanduser('~') + '/.saram.conf'
    with open(conf_file_path, 'r') as confFile:
        saram_conf = json.load(confFile)
except IOError:
    print('Cannot find ~/.saram.conf file')
    exit()

def saram_headers():
    return {
        'x-saram-username': saram_conf['username'],
        'x-saram-apikey': saram_conf['apiKey'],
        'x-saram-avatar': saram_conf['avatar'],
        'Content-type': 'application/json',
        'Accept': 'application/json'
    }

def saram_py2_new_section(token, data):
    url = saram_conf['base_url'] + 'api/' + token
    req = urllib2.Request(url, json.dumps(data), headers=saram_headers())
    req.get_method = lambda : 'PATCH'
    response = urllib2.urlopen(req)
    return response.read()
