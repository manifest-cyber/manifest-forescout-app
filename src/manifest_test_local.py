import argparse
import logging
import os

# Setup argument parsing
parser = argparse.ArgumentParser(description="This script tests your connection to the Manifest API")

# Alternate URL: Optional
parser.add_argument(
  '-t',
  '--token',
  type=str,
  help="REQUIRED: Specify a Manifest API token to use when authenticating. You can provide via this argument or as an env variable, e.g. `export MANIFEST_API_TOKEN=myToken`",
  default=os.getenv('MANIFEST_API_TOKEN')
)

# Alternate URL: Optional
parser.add_argument(
  '--url',
  type=str,
  help="Specify a different host URL for the Manifest API. This is useful for testing within a proxy or against a self-hosted Manifest instance.",
  default='https://api.manifestcyber.com'
)

parser.add_argument(
  '--agree',
  action='store_true',
  help="For testing, optionally specify to emulate consent to Manifest Cyber ToS, Privacy Policy, and applicable agreements.",
  default=False
)

parser.add_argument(
  '--includeassetfetch',
  action='store_true',
  help="For testing, optionally include a test to fetch a single asset from the target organization. Make sure the organization has uploaded the included test SBOM.",
  default=False
)

# Verbose: Optional
parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging (debug level).")

# Parse the arguments
args = parser.parse_args()

# Setup logging
if args.verbose:
  logging.basicConfig(level=logging.DEBUG,
                      format='%(asctime)s - %(levelname)s - %(message)s')
else:
  logging.basicConfig(level=logging.INFO,
                      format='%(asctime)s - %(levelname)s - %(message)s')

params = {
  'connect_manifest_url': 'https://api.manifestcyber.com',  # Default URL to use
  # 'connect_manifest_apitoken': 'foobar' # Set from args or env var
}

# Add our API token
if args.token:
  params['connect_manifest_apitoken'] = args.token
else:
  logging.error('No API token provided. Please provide an API token to use for authentication. Run with -help for more information.')
  exit(1)

# If an alternate URL was provided, use it
if args.url:
  params['connect_manifest_url'] = args.url

# Include optional consent agreement
params['connect_manifest_consent_agreements'] = bool(args.agree)

# Include optional asset fetch
params['connect_manifest_includeAssetListCheck'] = bool(args.includeassetfetch)

# Start our local test
logging.info('Starting local test of `manifest_test.py`...')

from manifest_test_base import test_manifest
response = test_manifest(params)

logging.info('Test complete. Results:')
logging.info(response)

logging.info('Exiting...')
