#!/usr/bin/env python

# Given a UUID, send a recurring beacon.

import json
import uuid
import sys
import pprint

import requests


url = 'http://localhost:8000/implants/beacon/'
command_url = 'http://localhost:8000/implants/command/'

implant_id = sys.argv[1]

print 'Implant ID: {implant_id}'.format(implant_id=implant_id)

request_dict = {
	'id': implant_id,
}
# TODO: Encryption/encoding?
request_body = json.dumps(request_dict)

r = requests.post(url, data=request_body)
if r.status_code != 200:
	print r.text
commands = json.loads(r.json())

command_ids = []
for command in commands:
	# This is where the real implant would actually perform the requested action
	# We just grab the ID so we can report success
	print 'Received command {type} "{argument}", marking completed'.format(type=command['command'], argument=command['argument'])
	command_ids.append(command['id'])

request_dict = {
	'id': implant_id,
	'success_commands': command_ids,
	'error_commands': [],
}

request_body = json.dumps(request_dict)
r = requests.post(command_url, data=request_body)
if r.status_code != 200:
	print r.text
response = r.json()
assert(type(response) == dict)
assert(len(response.keys()) == 0)
