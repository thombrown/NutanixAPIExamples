<#
#Ignore SSL certificate snippet for Powershell v5 and below. If using Powershell v6 or above, this is not necessary.
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
#End of SSL Certificate snippet
#>


#Enter login info
$clusterip = read-host "Enter Prism Central Cluster IP"
$creds = Get-Credential
$VMtoUpdate = "TomWin2019"
$categoryName = "Environment"
$categoryValue = "Dev"

#Which endpoint you are trying to hit
$Uri = "https://${clusterip}:9440/api/nutanix/v3/vms/list"
#Build the body
$body = @"
    {
        
    }
"@

#Pass the credentials in the header
$Header = @{
    "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($creds.UserName+":"+$creds.GetNetworkCredential().Password))
}

#Here is the actual API request. If using Powershell v6 or higher with a self signed certificate on Prism Central, use -SkipCertificateCheck on the end of the command.  If using Powershell v5 or lower, remove -SkipCertificateCheck
$response = Invoke-WebRequest -Method Post -Uri $Uri -Headers $Header -ContentType "application/json" -Body $body -SkipCertificateCheck
#Take the output and convert it from JSON to a readable format
$VMs = (ConvertFrom-Json -InputObject $response.content).entities

#Get the UUID of a specific VM
$VMuuid = ($VMs | Where-Object {$_.spec.name -eq $VMtoUpdate}).metadata.uuid
#Get the spec of that VM
$spec = Invoke-WebRequest -Method Get -Uri "https://${clusterip}:9440/api/nutanix/v3/vms/$VMuuid" -Headers $Header -ContentType "application/json" -Body $body -SkipCertificateCheck
#Take the output and convert it from JSON to a readable format
$VMspec = (ConvertFrom-Json -InputObject $spec.Content)
#Keep everything but the status key from the results
$payload = $VMspec | Select-Object spec,api_version,metadata
#Add a category to the VM. In this case I'm adding the default Environment:Dev category
$payload.metadata.categories | add-member -name "$CategoryName" -value "$CategoryValue" -Membertype NoteProperty -Force
#Convert the result back to JSON
$JSONpayload = ConvertTo-Json -InputObject $payload -Depth 10
#Send the updated VM specs back
$spec = Invoke-WebRequest -Method Put -Uri "https://${clusterip}:9440/api/nutanix/v3/vms/$VMuuid" -Headers $Header -ContentType "application/json" -Body $JSONpayload -SkipCertificateCheck
