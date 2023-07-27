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

# Assetnote check script
def verify_cve_2023_3519(target):
    # SAML assertion from Assetnots' work
    saml_assertion = """PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBJRD0icGZ4NDFkOGVmMjItZTYxMi04YzUwLTk5NjAtMWIxNmYxNTc0MWIzIiBWZXJzaW9uPSIyLjAiIFByb3ZpZGVyTmFtZT0iU1AgdGVzdCIgRGVzdGluYXRpb249Imh0dHA6Ly9pZHAuZXhhbXBsZS5jb20vU1NPU2VydmljZS5waHAiIFByb3RvY29sQmluZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCIgQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVVJMPSJodHRwOi8vc3AuZXhhbXBsZS5jb20vZGVtbzEvaW5kZXgucGhwP2FjcyI+CiAgPHNhbWw6SXNzdWVyPkE8L3NhbWw6SXNzdWVyPgogIDxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgogICAgPGRzOlNpZ25lZEluZm8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgIDxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz4KICAgICAgPGRzOlJlZmVyZW5jZSBVUkk9IiNwZng0MWQ4ZWYyMi1lNjEyLThjNTAtOTk2MC0xYjE2ZjE1NzQxYjMiPgogICAgICAgIDxkczpUcmFuc2Zvcm1zPgogICAgICAgICAgPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+CiAgICAgICAgICA8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+CiAgICAgICAgPC9kczpUcmFuc2Zvcm1zPgogICAgICAgIDxkczpEaWdlc3RWYWx1ZT5BPC9kczpEaWdlc3RWYWx1ZT4KICAgICAgPC9kczpSZWZlcmVuY2U+CiAgICA8L2RzOlNpZ25lZEluZm8+CiAgICA8ZHM6U2lnbmF0dXJlVmFsdWU+QTwvZHM6U2lnbmF0dXJlVmFsdWU+CiAgPC9kczpTaWduYXR1cmU+CiAgPHNhbWxwOk5hbWVJRFBvbGljeSBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyIgQWxsb3dDcmVhdGU9InRydWUiLz4KICA8c2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0IENvbXBhcmlzb249ImV4YWN0Ij4KICAgIDxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPgogIDwvc2FtbHA6UmVxdWVzdGVkQXV0aG5Db250ZXh0Pgo8L3NhbWxwOkF1dGhuUmVxdWVzdD4="""
    vuln_request = requests.post("https://" + target + "/saml/login", data={"SAMLRequest": saml_assertion}, verify=False, timeout=10)
    citrix_response = vuln_request.text
    # Check to see if the response contains strings identified by Assetnote
    state = "not_vulnerable"
    if "Matching policy not found while trying to process Assertion; Please contact your administrator" in citrix_response:
        state = "saml_disabled"
    if "Unsupported mechanisms found in Assertion; Please contact your administrator" in citrix_response:
        state = "patched"
    if "SAML Assertion verification failed; Please contact your administrator" in citrix_response:
        state = "vulnerable"
    return state

def check_citrix(target,check_cve_2023_3519):
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
                if check_cve_2023_3519:
                    # call the check function to verify if the system is vulnerable to CVE-2023-3519
                    verify_cve_2023_3519(target)
                    if verify_cve_2023_3519 == "vulnerable":
                        print(target + " - Vulnerable to CVE-2023-3519")

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
    # Add argument to check for CVE-2023-3519 vulnerability with --cve-2023-3519 flag
    parser.add_argument('--cve-2023-3519', action='store_true', help="Check for CVE-2023-3519 vulnerability via SAML (if enabled). SAML is not required for exploitation!!!")
    args = parser.parse_args()

    if args.cve_2023_3519:
        # if the --cve-2023-3519 flag is used set variable check_cve_2023_3519 to True
        check_cve_2023_3519 = True
    else:
        check_cve_2023_3519 = False

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
        check_citrix(target,check_cve_2023_3519)


if __name__ == "__main__":
    main()
