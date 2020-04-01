#Ignore SSL certificate snippet for Powershell v5 or below.  If using Powershell v6 or above, this snippet is not needed.
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

#Enter login info
$clusterip = read-host "Enter Prism Element Cluster IP"
$creds = Get-Credential
$VMtoFind = "PrismCentral"

#Which endpoint you are trying to hit
$Uri = "https://${clusterip}:9440/PrismGateway/services/rest/v2.0/vms/"
#Pass the credentials in the header
$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($creds.UserName+":"+$creds.GetNetworkCredential().Password))}
#Here is the actual API request
$response = Invoke-WebRequest -Method Get -Uri $Uri -Headers $Header 
#Take the output and convert it from JSON to a readable format
$VMs = (ConvertFrom-Json -InputObject $response.content).entities
#Get the UUID of a specific VM
$VMuuid = ($VMs | Where-Object {$_.Name -eq $VMtoFind}).uuid

#Build the body of a request to power on that VM
$body = @"
    {
        "transition": "ON",
        "uuid": "$VMuuid"
    }
"@

#Call the endpoint to set the power state of a specific VM
$uri = "https://${clusterip}:9440/PrismGateway/services/rest/v2.0/vms/$VMuuid/set_power_state"
#Store the response in a variable for error handling
$response = Invoke-WebRequest -Method Post -Uri $uri -Headers $Header -Body $body -ContentType "application/json"
