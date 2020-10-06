<#
This script is used against Prism Element to build an inventory of the hosts and their hardware stats.
Written by Thomas Brown (thomas.brown@nutanix.com)
#>

If ($PSVersionTable.PSVersion.Major -eq '5'){
#Ignore SSL certificate
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
}


#Enter login info
$clusterip = read-host "Enter Prism Element Cluster IP"
$creds = Get-Credential

#Which endpoint you are trying to hit
$Uri = "https://${clusterip}:9440/PrismGateway/services/rest/v2.0/hosts/"
#Pass the credentials in the header
$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($creds.UserName+":"+$creds.GetNetworkCredential().Password))}
#Here is the actual API request
If ($PSVersionTable.PSVersion.Major -eq '5'){
$response = Invoke-WebRequest -Method Get -Uri $Uri -Headers $Header
}
else {
    $response = Invoke-WebRequest -Method Get -Uri $Uri -Headers $Header -SkipCertificateCheck
}
#Take the output and convert it from JSON to a readable format
$hosts = (ConvertFrom-Json -InputObject $response.content).entities


$Output = foreach ($temphost in $hosts) {
    New-Object -TypeName PSObject -Property @{
      name = $temphost.name
      ipmi_address = $temphost.ipmi_address 
      hypervisor_address = $temphost.hypervisor_address
      CVM_IP = $temphost.service_vmexternal_ip
      Node_Serial = $temphost.serial
      block_serial = $temphost.block_serial
      block_location = $temphost.position.name
      model = $temphost.block_model_name
      hypervisor = $temphost.hypervisor_full_name
      CPU = $temphost.cpu_model
      Cores = $temphost.num_cpu_cores
      Sockets = $temphost.num_cpu_sockets
      memory_capacity_in_GiB = $temphost.memory_capacity_in_bytes/1074000000
      SSD_Capacity_in_TiBs = $temphost.usage_stats.'storage_tier.ssd.capacity_bytes'/1000000000000

    } | Select-Object name,ipmi_address,hypervisor_address,CVM_IP,Node_Serial,block_serial,block_location,model,hypervisor,CPU,Cores,Sockets,memory_capacity_in_GiB,SSD_Capacity_in_TiBs
  }
  $Output | Export-Csv $env:TEMP\hosts.csv
  
  Write-Host "File written to " $env:TEMP\hosts.csv
