import logging
import json
import urllib.request
import ssl

def check_consent(params):
    if not params.get('connect_manifest_consent_agreements', False):
        logging.info('You must consent to abide by all applicable terms and agreements between your organization and Manifest Cyber. Please reinstall the integration and agree to the terms.')
        return False
    logging.debug('You agreed to abide by all applicable terms and agreements between your organization and Manifest Cyber. Test continuing...')
    return True

def perform_request(url, headers, ssl_context, method='GET'):
    request = urllib.request.Request(url, method=method, headers=headers)
    try:
        response = urllib.request.urlopen(request, context=ssl_context)
        # Check the content type of the response
        content_type = response.headers.get('Content-Type', '')
        content = response.read()

        if 'application/json' in content_type:
            if content:  # Check if the response body is not empty
                return json.loads(content)
            else:
                return {"error": "Empty response", "status": response.status}
        elif 'text/plain' in content_type:
            return content.decode('utf-8')  # Decode bytes to string if plain text
        else:
            logging.warning(f'Unexpected content type: {content_type}')
            return {"error": "Unexpected content type", "status": response.status, "content": content.decode('utf-8')}

    except urllib.error.HTTPError as e:
        content = e.read().decode()
        return {"error": content or "Unknown error", "status": e.code}
    except urllib.error.URLError as e:
        raise Exception(f"URL Error: {e.reason}")

manifest_to_ct_props_map = {
  "assetId": "connect_manifest_assetid",
  "sbomId": "connect_manifest_sbomid",
  "relationship": "connect_manifest_sbom_relationship",
  "coordinates": "connect_manifest_coordinates",
}

def test_manifest(params):
    logging.info('Beginning Manifest Test...')

    response = {}
    manifest_base_url = params['connect_manifest_url']
    manifest_api_token = params['connect_manifest_apitoken']

    # Check user consent
    if not check_consent(params):
        response['succeeded'] = False
        response['result_msg'] = 'Consent not provided.'
        return response

    # Setup logging and SSL context
    masked_key = f"{manifest_api_token[0]}{'*' * (len(manifest_api_token) - 2)}{manifest_api_token[-1]}" if len(manifest_api_token) > 1 else '*'
    ssl_context = ssl.create_default_context()
    headers = {'Authorization': f'Bearer {manifest_api_token}'}
    logging.info(f'Attempting to test connection to Manifest with URL "{manifest_base_url}" and API key "{masked_key}"')

    # Perform network connectivity test
    try:
        health_check = perform_request(manifest_base_url + '/v1/health', headers, ssl_context)
        logging.debug('Health check successful.')
    except Exception as e:
        logging.error(f'Failed during health check: {e}')
        response['succeeded'] = False
        response['result_msg'] = str(e)
        return response

    # Authentication test
    try:
        auth_check = perform_request(manifest_base_url + '/v1/organization', headers, ssl_context)
        logging.debug('Authentication successful.')
    except Exception as e:
        logging.error(f'Failed during authentication test: {e}')
        response['succeeded'] = False
        response['result_msg'] = str(e)
        return response
    
    # Optional asset list check
    # Attempt to fetch a single asset from the target organization
    # Make sure the organization has uploaded the included test SBOM
    if params['connect_manifest_includeassetlistcheck']:
      firmware = '7.20.1'
      model = 'm2025-le_firmware'
      vendor = 'axis'
      assets_list_query_string = urllib.parse.quote(
          '?limit=10&filters=[{ "field": "assetName", "value": "' +  model + '@' + firmware + '" }, { "field": "assetActive", "value": "true" }]',
          safe='?&='
      )
      
      try:
          asset_list_check = perform_request(manifest_base_url + '/v1/assets' + assets_list_query_string, headers, ssl_context)
          logging.debug('Asset list returned successfully (still need to check result accuracy).')
      except Exception as e:
          logging.error(f'Failed during authentication test: {e}')
          response['succeeded'] = False
          response['result_msg'] = str(e)
          return response
      else:
          if asset_list_check['success'] and asset_list_check['queryInfo']['totalReturn'] == 1:
              package_url_no_version = 'pkg:cpe/' + vendor + '/' + model
              if asset_list_check['data'][0]['packageUrlNoVersion'] != package_url_no_version:
                response['succeeded'] = False
                response['result_msg'] = f'Expected asset name to be {package_url_no_version}, but got {asset_list_check["data"][0]["packageUrlNoVersion"]}'
                logging.debug('Test connection failed to Manifest (Asset List Fetch).')
              else:
                properties = {}
                return_values = asset_list_check["data"][0]
                for key, value in return_values.items():
                  if key in manifest_to_ct_props_map:
                    properties[manifest_to_ct_props_map[key]] = value

                response['properties'] = properties
                logging.debug('Asset list accuracy check passed - received 1 asset with expect packageUrlNoVersion.')
          else:
              response['succeeded'] = False
              response['result_msg'] = 'Expected 1 asset to be returned, but got ' + str(asset_list_check['totalReturn'])
              logging.debug('Test connection failed to Manifest (Asset List Fetch).')
    else:
      logging.debug('Skipping asset list check.')


    # If we got this far, all tests passed...
    response['succeeded'] = True
    response['result_msg'] = 'All tests passed successfully.'
    logging.info('Completed Manifest Test...')
    return response
