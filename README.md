# Manifest-Forescout-App 1.0.0
eyeExtend Connect App for Manifest allows Forescout to connect to the Manifest API and retrive SBOM and vulnerability data for devices in the Forescout network.

## Installation in Forescout
1. Download the `manifest-forescout.zip` file from this repo.
2. Open Forescout Console > Options. Search for 'Connect' and go to the 'App' tab.
3. Click 'Import' and select the `manifest-forescout.zip` file. Note you'll need to make sure signature verification is disabled in the Connect options.
4. You should now see installation logs and (hopefully) noting that all scripts validated successfully and system config was successfully reloaded. Click 'Close' in the log window and a 'System Description' window with an 'Add' button in the top right.
4. Click 'Add' and you should see the Manifest connection configuration window. Enter your API token (and adjust the API URL as necessary), then click 'Next'. Assign any CounterAct devices and Proxy Settings as necessary, then click Next. Scroll over and click the checkbox in the Manifest Agreements section, then click 'Finish'.
5. We're going to test the app, but before doing that we'll want to make sure we've uploaded the `test_sbom.json` SBOM included in this repository (we'll remove this requirement in production). This ensures the Manifest tenant has the asset the test is looking for so it can run a test to fetch asset information. Once you've done this, go back to the Forescout console.
7. In the 'System Description' window you should now see an entry in the table with the Manifest API url. If you select that entry, you'll see the 'Test' option on the right now be highlighted/available. Click 'Test' to verify the connection to the Manifest API. You should see a 'Test Successful' message ("All tests passed successfully"). Click 'Close' and then 'OK' to close the System Description window.
8. If all looks good, click 'OK' to close the window, which should take you back to the 'Connect' options and now show the Manifest app installed with status 'Running'. **Make sure to click 'Apply' in the bottom right to save the changes, or you'll lose all of the above!**
9. After clicking Apply, you shoud see the config/logging window open, and then be good to go. *Note: You may need to click 'Apply' in this window before you can run the 'Test' in #6 above.*
10. You should now be able to create policies and rules in Forescout to leverage Manifest data.
11. If you need to update the app, you'll need to remove the existing app and re-import the new version (repeat steps 3-10).


## Usage Prereqs:
The Manifest integration app looks for 3 properties on the device. These are:
  - `mfst_vendor`: The vendor of the device firmware.
  - `mfst_model`: The model of the device (or its firmware, as applicable).
  - `mfst_firmware`: The firmware version of the device.


## Usage
- The app will automatically fetch SBOM and vulnerability data for devices in the Forescout network. This data will be available in the Forescout console for use in policies and rules.
- Create a mapping between any collected firmware (for example, from Cloud Data Exchange) and the device's `mfst_vendor`, `mfst_model`, and `mfst_firmware` properties. This will allow the app to fetch the correct SBOM and vulnerability data for the device.
- The integration expects that the appropriate SBOMs are available in the Manifest tenant. If the SBOMs are not available, the app will not be able to fetch the SBOM and vulnerability data for the device.


## Manifest Properties
The integration app will attempt to attach the following properties in Forescout for each device (when available):
- `Manifest Asset ID`: The ID of the asset in Manifest.
- `Manifest SBOM ID`: The ID of the SBOM in Manifest.
- `Manifest SBOM Upload Date`: The date the SBOM was uploaded and the asset was created in Manifest.
- `Manifest SBOM Download URL`: A URL to download the SBOM from Manifest.
- `Manifest SBOM Relationship`: Indicates whether the SBOM is a first- or third-party (external) entity.
- `Manifest Coordinates`: Derived coordinates (based on CPE and PURLs) for the asset in Manifest.
- `Manifest Risk Score`: A numerical value representing the risk score of the asset in the Manifest platform. 3 is high risk, 2 is medium risk, and 1 is low risk.
- `Total Vulnerabilities Count`: Total number of vulnerabilities found by Manifest in the SBOM for this asset.
- `Critical Vulnerabilities Count`: Critical number of vulnerabilities found by Manifest in the SBOM for this asset.
- `High Vulnerabilities Count`: High number of vulnerabilities found by Manifest in the SBOM for this asset.
- `Medium Vulnerabilities Count`: Medium number of vulnerabilities found by Manifest in the SBOM for this asset.
- `Low Vulnerabilities Count`: Low number of vulnerabilities found by Manifest in the SBOM for this asset.
- `KEV Vulnerabilities Count`: Number of KEV (Known Exploitable Vulnerabilities) found by Manifest in the SBOM for this asset.
 

## Local Testing
- Run `python manifest_test_local.py --url https://api.manifestcyber.com --token <API_KEY> --agree -v` to test the connection to the Manifest API. You can instead run with `--help` to see all available options.
- Before you run the above command with `--includeassetfetch`, you will need to upload the `test_sbom.json` file included in this repository to the Manifest tenant you're testing with. This will ensure a matching asset/sbom are found and available for the test.

## Development & Notes
- We cannot access some common Python libraries from within Forescout. Among those are `requests`, `eval`, `exec`, `open`, and `os` (e.g. for env vars). We can use `urllib` for requests, so make sure you're following suit. We are unable to use `print()` for debugging, so we'll need to use `logger.info()` or `logger.debug()` instead.
- When in FS, we have to tail logs in `/usr/local/forescout/plugin/connect_module/python_logs` to see what's happening, and even then need to make sure we have full debugging enabled by running `fstool connect debug 5`. 
- Local imports don't appear to always work well in FS, so the `manifest_test.py` is a direct copy of `manifest_test_base.py` so that there are no external dependencies (unlike our `manifest_test_local.py` that imports as we'd expect). This is a pain, and there may be a workaround, but for now any tests you add to the _base file should be copied into _test file.
- See Manifest's internal credential manager for test credentials to our Forescout development tenant and VM's.
- The `manifest_forescout.zip` file is presently manually built locally and should be rebuilt with any changes to the app. We'll automate this (and remove this notice) as part of releases via CI.
- Links:
  - [Forescout Cloud Data Exchange module](https://docs.forescout.com/bundle/cloud-data-exchange-plugin-v1-0-6-h/page/about-the-cde-integration.html): We currently depend on data from this module to derive firmware model, version, & vendor.
  - [Forescout eyeExtend-Connect Reference repos](https://github.com/Forescout/eyeExtend-Connect/tree/master): Example integration apps to pull from. The `Sample App 1.1.1`, `Trend Micro Apex 1.0.0`, and `Symantec-1.0.0` apps were used as reference. We may dupe this app as a PR into that repo once it's ready for production.
  - [Forescout Connect App Video Guides](https://www.youtube.com/watch?v=kFyLVD8q8yE&list=PL2HYJud3zBqcjUoiJzVG33_ubuRqv3crQ): YT video playlist from FS. Pretty outdated and not super helpful outside of some nuanced instances, but gives example of a super basic app and the relationships between system.conf, property.conf, and various scripts.
