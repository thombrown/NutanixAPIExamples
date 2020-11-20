<#
This script is used against Prism Central to build an inventory of the hosts and their hardware stats.
Written by Thomas Brown (thomas.brown@nutanix.com)
Written and tested against Powershell v7.1.0 and Powershell v5.1
#>

function Get-PCClusters {
<#
  .DESCRIPTION
   This function connects to Prism Central to obtain a list of the Prism Element clusters registered.
  .PARAMETER PrismCentralIP
    Specifies the Prism Central you wish to connect.  Can be FQDN or IP address.
  #>
  [CmdletBinding()]

    param (
        [Parameter(Mandatory=$true)]
        [string]$PrismCentralIP,
        [PSCredential]$PrismCentralCredentials
    )
    

    #Which endpoint you are trying to hit
    $Uri = "https://${PrismCentralip}:9440/api/nutanix/v3/clusters/list"
    #Build the body
    $body = @"
        {
        }
"@

    #Pass the credentials in the header
    $Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PrismCentralCredentials.UserName+":"+$PrismCentralCredentials.GetNetworkCredential().Password))}
    #Here is the actual API request
    If ($PSVersionTable.PSVersion.Major -eq '5'){
        #Add Error Handling
        $response = Invoke-WebRequest -Method Post -Uri $Uri -Headers $Header -ContentType "application/json" -Body $body
    }
    else {
        #Add Error Handling
        $response = Invoke-WebRequest -Method Post -Uri $Uri -Headers $Header -SkipCertificateCheck -ContentType "application/json" -Body $body
    }
    #Take the output and convert it from JSON to a readable format
    $clusters = (ConvertFrom-Json -InputObject $response.content).entities

    $script:PCOutput = foreach ($tempcluster in $clusters) {
        New-Object -TypeName PSObject -Property @{
        name = $tempcluster.status.name
        clusterip = $tempcluster.status.resources.network.external_ip
        AOSversion = $tempcluster.status.resources.config.build.version

        } | Select-Object name,clusterip,AOSversion | Where-Object {$_.clusterip}
    }

    return $PCOutput

}

function Get-PEHosts {
    <#
  .DESCRIPTION
   This function is used to Connect to Prism Element and return the host inventory.
  .PARAMETER PrismElementIP
    Specifies the Prism Element you wish to connect.  Can be FQDN or IP address.
  #>
  [CmdletBinding()]

    param (
        [Parameter(Mandatory=$true)]
        [string]$PrismElementIP,
        [PSCredential]$PrismElementCredentials
    )
    

    #Which endpoint you are trying to hit
    $Uri = "https://${PrismElementIp}:9440/PrismGateway/services/rest/v2.0/hosts/"
    #Pass the credentials in the header
    $Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PrismElementCredentials.UserName+":"+$PrismElementCredentials.GetNetworkCredential().Password))}
    #Here is the actual API request
    If ($PSVersionTable.PSVersion.Major -eq '5'){
        $hostResponse = Invoke-WebRequest -Method Get -Uri $Uri -Headers $Header
    }else {
        $hostResponse = Invoke-WebRequest -Method Get -Uri $Uri -Headers $Header -SkipCertificateCheck
    }
    #Take the output and convert it from JSON to a readable format
    $hosts = (ConvertFrom-Json -InputObject $hostResponse.content).entities


    #Which endpoint you are trying to hit
    $Uri = "https://${PrismElementIP}:9440/PrismGateway/services/rest/v2.0/cluster/"
    #Pass the credentials in the header
    $Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PrismElementCredentials.UserName+":"+$PrismElementCredentials.GetNetworkCredential().Password))}
    #Here is the actual API request
    If ($PSVersionTable.PSVersion.Major -eq '5'){
        $clusterResponse = Invoke-WebRequest -Method Get -Uri $Uri -Headers $Header
    }else {
        $clusterResponse = Invoke-WebRequest -Method Get -Uri $Uri -Headers $Header -SkipCertificateCheck
    }
    #Take the output and convert it from JSON to a readable format
    $cluster = (ConvertFrom-Json -InputObject $clusterResponse.content)
    
    $script:inventory = foreach ($temphost in $hosts) {
        New-Object -TypeName PSObject -Property @{
        hostname = $temphost.name
        clusterName = $cluster.name
        clusterUUID = $temphost.cluster_uuid
        ipmi_address = $temphost.ipmi_address 
        hypervisor_address = $temphost.hypervisor_address
        CVM_IP = $temphost.service_vmexternal_ip
        Node_Serial = $temphost.serial
        block_serial = $temphost.block_serial
        block_location = $temphost.position.name
        block_slot = $temphost.position.ordinal
        model = $temphost.block_model_name
        AOSVersion = $cluster.version
        hypervisor = $temphost.hypervisor_full_name
        CPU = $temphost.cpu_model
        Cores = $temphost.num_cpu_cores
        Sockets = $temphost.num_cpu_sockets
        memory_capacity_in_GiB = $temphost.memory_capacity_in_bytes/1074000000
        SSD_Capacity_in_TiBs = $temphost.usage_stats.'storage_tier.ssd.capacity_bytes'/1100000000000
        numberOfVMs = $temphost.num_vms-1
        bios_version = $temphost.bios_version
        bmc_version = $temphost.bmc_version

        } | Select-Object hostname,clusterName,clusterUUID,ipmi_address,hypervisor_address,CVM_IP,Node_Serial,block_serial,block_slot,model,AOSVersion,hypervisor,CPU,Cores,Sockets,memory_capacity_in_GiB,SSD_Capacity_in_TiBs,numberOfVMs,bios_version,bmc_version
    }

    return $inventory
    
}

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
    
    $clusterip = read-host "Enter Prism Central Cluster IP"
    $PCcreds = Get-Credential
    $answer = read-host "This script will connect to each Prism Element cluster that is registered to Prism Central. Would you like to use the same credentials to connect to Prism Central and all Prism Element clusters? Y/N"
    $clusters = Get-PCClusters -PrismCentralIP $clusterip -PrismCentralCredentials $PCcreds
    
    $Date = (get-date).ToString("yyyy-MM-dd-HHmmss")

        $fileToCheck = "$env:TEMP\nutanix_inventory-$Date.csv"
        if (Test-Path $fileToCheck -PathType leaf)
        {
            Remove-Item $fileToCheck
        }
    
    if (($answer -eq 'n') -or ($answer -eq 'N') -or ($answer -eq 'No') -or ($answer -eq 'no')){
        $PECreds = @{}
        foreach ($temp in $clusters) {
            Write-host "Please enter credentials for Prism Element Cluster " $temp.name
            $tempCreds = Get-Credential
                $PECreds.add($temp.clusterip,$tempCreds)
        }

                foreach ($i in $PECreds.GetEnumerator()) {                
                $output = Get-PEHosts -PrismElementIP $i.Key -PrismElementCredentials $i.Value
                $Output | Export-Csv $env:TEMP\nutanix_inventory-$Date.csv -Append -NoTypeInformation
                
                }
                Write-Host "File written to " $env:TEMP\nutanix_inventory-"$Date".csv
                Invoke-Item $env:TEMP\nutanix_inventory-$Date.csv
    }

    if (($answer -eq 'y') -or ($answer -eq 'Y') -or ($answer -eq 'Yes') -or ($answer -eq 'yes')){
        foreach ($temp in $clusters){
            $output = Get-PEHosts -PrismElementIP $temp.clusterip -PrismElementCredentials $PCcreds
            $Output | Export-Csv $env:TEMP\nutanix_inventory-$Date.csv -Append -NoTypeInformation
        }
        Write-Host "File written to " $env:TEMP\nutanix_inventory-$Date.csv
            Invoke-Item $env:TEMP\nutanix_inventory-$Date.csv
    }
