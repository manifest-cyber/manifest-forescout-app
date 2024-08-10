# This script is used to test Manifest integration connectivity from within Forescout
# Forescout should populate the `params` dictionary with the keys we need.
# If running/testing locally, you can use `manifest_test_local.py`, which uses argparse and env vars to populate `params` and then wraps the same `testManifest` function from `manifest_test_base.py`
import logging

logging.info('Starting Manifest Test Script...')

from manifest_test_base import test_manifest
response = test_manifest(params)

logging.info('Test complete. Results:')
