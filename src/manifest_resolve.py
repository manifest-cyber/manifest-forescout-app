'''
Copyright © 2020 Forescout Technologies, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

import logging
import base64
import jwt
import hashlib
import time
import json
import ssl
import urllib.request
from utils import perform_request
from utils import check_consent


manifest_to_ct_props_map = {
  "product": "connect_manifest_assetid",
  "entity_id": "connect_manifest_sbomid",
}

response = {}

logging.info("Got the following params:")
for key, value in params.items():
  logging.info(f"{key}: {value}")

manifest_base_url = params.get('connect_manifest_url')
manifest_api_token = params.get('connect_manifest_apitoken')

ssl_context = ssl.create_default_context()
headers = {'Authorization': f'Bearer {manifest_api_token}'}

if not check_consent(params):
  response['succeeded'] = False
  response['result_msg'] = 'Consent not provided.'
  logging.info('Consent to Manifest terms & agreements not provided.')
