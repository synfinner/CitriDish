#!/usr/bin/env python3

import argparse
import requests
import sys
import ssl

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings()

# Citrix Gateways and AAAs have two different paths that can be used to identify them.
# Define constants for the paths
# Citrix Gateway Path
CGW_PATH = "/vpn/logout.html"
# Citrix AAA path
AAA_PATH = "/logon/LogonPoint/tmindex.html"


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
