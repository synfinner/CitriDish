
# This is a PowerShell script that can be used to identify Citrix Gateways and AAA servers.
# Thanks, @UK_Daniel_Card. ;) 
param (
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias("targets")]
    [String[]]
    $Target,

    [Parameter(Mandatory=$false)]
    [String]
    $File,

    [Parameter(Mandatory=$false)]
    [Switch]
    $CVE_2023_3519
)

function Verify-CVE-2023-3519 {
    # SAML assertion from Assetnote's work
    $SAMLAssertion = @"
    <SAMLp:AuthnRequest xmlns:SAMLp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="pfx41d8ef22-e612-8c50-9960-1b16f15741b3" IssueInstant="http://www.w3.org/2001/XMLSchema-instance" ProtocolBinding="http://www.w3.org/2001/XMLSchema-instance">
        <SAML:Issuer xmlns:SAML="urn:oasis:names:tc:SAML:2.0:assertion">http://www.example.com/SSOServer/php</SAML:Issuer>
        <SAMLp:NameIDPolicy xmlns:SAMLp="urn:oasis:names:tc:SAML:2.0:protocol" Format="http://www.example.com/SSOServer/php"></SAMLp:NameIDPolicy>
    </SAMLp:AuthnRequest>
"@

    $Headers = @{
        "Content-Type" = "application/x-www-form-urlencoded"
    }

    $VulnRequest = Invoke-RestMethod -Uri "https://${target}/saml/login" -Method Post -Body @{ "SAMLRequest" = $SAMLAssertion } -Headers $Headers -UseBasicParsing -TimeoutSec 10
    $CitrixResponse = $VulnRequest.RawContent

    # Check to see if the response contains strings identified by Assetnote
    $state = "not_vulnerable"
    if ($CitrixResponse.Contains("Matching policy not found while trying to process Assertion; Please contact your administrator")) {
        $state = "saml_disabled"
    }
    if ($CitrixResponse.Contains("Unsupported mechanisms found in Assertion; Please contact your administrator")) {
        $state = "patched"
    }
    if ($CitrixResponse.Contains("SAML Assertion verification failed; Please contact your administrator")) {
        $state = "vulnerable"
    }

    return $state
}

function Check-Citrix {
    param (
        [String]
        $Target,

        [Switch]
        $CVE_2023_3519
    )

    # Citrix Gateways and AAAs have two different paths that can be used to identify them.
    # Define constants for the paths
    # Citrix Gateway Path
    $CGW_PATH = "/vpn/logout.html"
    # Citrix AAA path
    $AAA_PATH = "/logon/LogonPoint/tmindex.html"

    $url = "https://$Target"
    $cgw_url = $url + $CGW_PATH
    $aaa_url = $url + $AAA_PATH

    try {
        # Perform a GET request to the Citrix Gateway URL and AAA URL
        $cgw_response = Invoke-RestMethod -Uri $cgw_url -UseBasicParsing -ErrorAction Stop
        $aaa_response = Invoke-RestMethod -Uri $aaa_url -UseBasicParsing -ErrorAction Stop

        if ($cgw_response.StatusCode -eq 200) {
            # If the status code is 200, check for specific content to identify it as a Citrix Gateway
            if ($cgw_response -match "<title>Citrix Gateway</title>" -or $cgw_response -match "/vpn/js/logout_view.js?v=") {
                $lastModified = [DateTime]::ParseExact($cgw_response.Headers["Last-Modified"], "ddd, dd MMM yyyy HH:mm:ss Z", $null)
                $potentiallyVuln = $false

                # Loop through the patched versions array and check if the lastModified variable is less than the timestamp
                foreach ($patchedVersion in @(
                    @{
                        "version" = "13.0-91.13"
                        "timestamp" = "Fri, 07 Jul 2023 15:39:40 GMT"
                    },
                    @{
                        "version" = "13.1-49.13"
                        "timestamp" = "Mon, 10 Jul 2023 17:41:17 GMT"
                    },
                    @{
                        "version" = "13.1-49.13"
                        "timestamp" = "Mon, 10 Jul 2023 18:36:14 GMT"
                    }
                )) {
                    if ($lastModified -lt [DateTime]::ParseExact($patchedVersion["timestamp"], "ddd, dd MMM yyyy HH:mm:ss Z", $null)) {
                        $potentiallyVuln = $true
                    }
                }

                # If potentiallyVuln is True, print the host or IP and that it is a Citrix Gateway and potentially vulnerable
                if ($potentiallyVuln) {
                    Write-Output "$Target - Potentially vulnerable Citrix Gateway identified (CVE-2023-3519)"
                }
                else {
                    Write-Output "$Target - Citrix Gateway identified"
                }

                if ($CVE_2023_3519) {
                    # Call the Verify-CVE-2023-3519 function to verify if the system is vulnerable to CVE-2023-3519
                    $vulnState = Verify-CVE-2023-3519 -Target $Target
                    if ($vulnState -eq "vulnerable") {
                        Write-Output "$Target - Vulnerable to CVE-2023-3519"
                    }
                }
            }
        }

        if ($aaa_response.StatusCode -eq 200) {
            # If the status code is 200, check for specific content to identify it as a Citrix AAA
            if ($aaa_response -match '_ctxstxt_NetscalerAAA') {
                Write-Output "$Target - Citrix AAA identified"
            }
        }
    }
    catch {
        # Print an error message if there was an issue with the request
        Write-Output "$Target - Error: $($_.Exception.Message)"
    }
}

if ($CVE_2023_3519) {
    # If the --cve-2023-3519 switch is used, set the $CVE_2023_3519 variable to $true
    $CVE_2023_3519 = $true
}
else {
    $CVE_2023_3519 = $false
}

if ($File) {
    try {
        $targets = Get-Content $File
    }
    catch {
        Write-Output "Error: File not found."
        Exit 1
    }
}
elseif ($Target) {
    $targets = $Target
}
else {
    Write-Output "Usage: ./citridish.ps1 [-CVE_2023_3519] -Target <ip address or hostname> [-File <file path>]"
    Exit 1
}

foreach ($target in $targets) {
    Check-Citrix -Target $target -CVE_2023_3519 $CVE_2023_3519
}
