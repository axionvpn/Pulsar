#!/usr/bin/env python

# Generate a UUID, print it, and perform an initial checkin.

import json
import uuid

import requests


url = 'http://localhost:8000/implants/beacon/'


implant_id = unicode(uuid.uuid4())

print 'Implant ID: {implant_id}'.format(implant_id=implant_id)

request_dict = {
	'id': implant_id,
	'group': 'testgroup',
	'beacon_interval': 1,
	'beacon_jitter': 0,
	'relay_host': 'localhost',
	'relay_port': 8000,
}
# TODO: Encryption/encoding?
request_body = json.dumps(request_dict)

r = requests.post(url, data=request_body)
if r.status_code != 200:
	print r.text
print r.json()
