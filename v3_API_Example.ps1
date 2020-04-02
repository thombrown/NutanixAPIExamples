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

#Enter login info
$clusterip = read-host "Enter Prism Central Cluster IP"
$creds = Get-Credential
$VMtoFind = "PrismCentral"

#Which endpoint you are trying to hit
$Uri = "https://${clusterip}:9440/api/nutanix/v3/vms/list"
#Build the body
$body = @"
    {
        
    }
"@
#Pass the credentials in the header
$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($creds.UserName+":"+$creds.GetNetworkCredential().Password))}
#Here is the actual API request. If using Powershell v6 or higher with a self signed certificate on Prism Central, use -SkipCertificateCheck on the end of the command
$response = Invoke-WebRequest -Method Post -Uri $Uri -Headers $Header -ContentType "application/json" -Body $body
#Take the output and convert it from JSON to a readable format
$VMs = (ConvertFrom-Json -InputObject $response.content).entities
#Get the UUID of a specific VM
$VMuuid = ($VMs | Where-Object {$_.spec.name -eq $VMtoFind}).metadata.uuid


<#
Create VM from a cloned image

"metadata": {
     "kind":"vm"
 },
 "spec": {
     "name":"test",
     "resources": {
         "disk_list": [
             {
                 "data_source_reference": {
                     "kind": "image",
                     "uuid": "a91f56a0-2133-4080-b6b4-60961e94dad7"
                 },
                 "device_properties": {
                     "device_type": "DISK",
                     "disk_address": {
                         "adapter_type": "SCSI",
                         "device_index": 0
                     }
                 }
             }
         ],
         "memory_size_mib": 1024,
         "num_sockets": 1,
         "num_vcpus_per_socket": 1,
         "power_state": "OFF"
     }
 }
}

#>


<#
Example of cloning from existing VM with sysprep

{
  "metadata":{
     "kind":"vm"
  },
  "spec":{
     "name":"VMCLONED001",
     "cluster_reference":{
        "kind":"cluster",
        "name":"CLUSTERNUTA001",
        "uuid":"00058128-10da-0XX-2c1f-98039b05d593"
     },
     "resources":{
        "guest_customization":{
           "is_overridable":false,
           "sysprep":{
              "install_type":"PREPARED",
              "unattend_xml":"FNjaGVtYSgICm9(...)1cD5BZG1pbmlz="
           }
        },
        "parent_reference":{
           "kind":"vm",
           "uuid":"b00cc669-cb2d-4235-aXXX-ff9b234bf8c9",
           "name":"GoldenMaster001"
        },
        "power_state":"OFF"
     }
  }
}


#>
 
 
