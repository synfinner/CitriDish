#!/usr/bin/env python3

import argparse
import requests
import sys
import datetime

# Author: @synfinner
# Credit to Deutsche Telekom CERT for the patched versions array

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings()

# Citrix Gateways and AAAs have two different paths that can be used to identify them.
# Define constants for the paths
# Citrix Gateway Path
CGW_PATH = "/vpn/logout.html"
# Citrix AAA path
AAA_PATH = "/logon/LogonPoint/tmindex.html"

# Patched versions array. Credit to Deutsche Telekom CERT
PATCHED_VERSIONS = [
    {"version": "13.0-91.13", "timestamp": "Fri, 07 Jul 2023 15:39:40 GMT"},
    {"version": "13.1-49.13", "timestamp": "Mon, 10 Jul 2023 17:41:17 GMT"},
    {"version": "13.1-49.13", "timestamp": "Mon, 10 Jul 2023 18:36:14 GMT"}
]

def check_citrix(target):
    # Define url variable with https and the ip address or hostname
    url = "https://" + target.strip()
    # Define the citrix gateway url by adding the citrix gateway path to the url variable
    cgw_url = url + CGW_PATH
    # Define the citrix aaa url by adding the citrix aaa path to the url variable
    aaa_url = url + AAA_PATH

    try:
        # Perform a get request to the citrix gateway url and aaa url
        cgw_response = requests.get(cgw_url, verify=False)
        aaa_response = requests.get(aaa_url, verify=False)

        if cgw_response.status_code == 200:
            # If the status code is 200, check for specific content to identify it as a citrix gateway
            if "<title>Citrix Gateway</title>" in cgw_response.text or "/vpn/js/logout_view.js?v=" in cgw_response.text:
                # Print the host or ip and that it is a citrix gateway
                # set last_modified to the last modified header in datetime format
                last_modified = datetime.datetime.strptime(cgw_response.headers["Last-Modified"], "%a, %d %b %Y %H:%M:%S %Z")
                potentially_vuln = False
                # Loop through the patched versions array and if the last_modified variable is less than the timestamp set potentially_vuln to True
                for patched_version in PATCHED_VERSIONS:
                    if last_modified < datetime.datetime.strptime(patched_version["timestamp"], "%a, %d %b %Y %H:%M:%S %Z"):
                        potentially_vuln = True
                # If potentially_vuln is True, print the host or ip and that it is a citrix gateway and potentially vulnerable
                if potentially_vuln:
                    print(target + " - Potentially vulnerable Citrix Gateway identified (CVE-2023-3519)")
                else:
                    print(target + " - Citrix Gateway identified")

        if aaa_response.status_code == 200:
            # If the status code is 200, check for specific content to identify it as a citrix aaa
            if '_ctxstxt_NetscalerAAA' in aaa_response.text:
                # Print the host or ip and that it is a citrix aaa
                print(target + " - Citrix AAA identified")

    except requests.exceptions.RequestException as e:
        # Print an error message if there was an issue with the request
        print(target + " - Error: " + str(e))


def main():
    parser = argparse.ArgumentParser(description="Identify if a system is running Citrix Gateway, or Citrix AAA.")
    parser.add_argument('targets', nargs='*', help="The IP address(es) or hostname(s) to check.")
    parser.add_argument('--file', '-f', help="Read targets from a file (one IP/hostname per line).")
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, 'r') as file:
                targets = file.read().splitlines()
        except FileNotFoundError:
            print("Error: File not found.")
            sys.exit(1)
    elif args.targets:
        targets = args.targets
    else:
        print("Usage: python3 citridish.py [options] <ip address or hostname>")
        sys.exit(1)

    for target in targets:
        check_citrix(target)


if __name__ == "__main__":
    main()
