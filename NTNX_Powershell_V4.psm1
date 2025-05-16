#Install this module using Import-Module
#Author: Thomas Brown (thomas.brown@nutanix.com)

Write-Host "This Powershell module is not officially supported by Nutanix.  Any usage is at your own risk. 

It uses the Nutanix v4 API hosted by Prism Central which requires PC 2024.3 or later and AOS 7.0 or later.  To find out more, read here - https://www.nutanix.dev/api-reference-v4/"
function Set-NTNXCredentials
{
  <#
  .DESCRIPTION
   This function is used to authenticate to Prism Central.
  .PARAMETER Server
    Specifies the Prism Central with which you wish to connect.  Can be FQDN or IP address.
  .PARAMETER username
    The user you wish to connect.  If left blank you will be prompted for credentials.
  .PARAMETER password
    The password for the user you wish to connect. If left blank you will be propmted for credentials.
  .PARAMETER apiKey
    API Key associated with a pre-created user account.  Optional parameter.  If you do not have an API key you can use user name password or you can use New-NTNXAPIKey to generate an API key.
  .EXAMPLE
        New-NTNXAPIKey
  .EXAMPLE
        New-NTNXAPIKey -server 10.42.157.39 -credential admin
  .EXAMPLE
        New-NTNXAPIKey -server 10.42.157.39 -apiKey b68fbbbad38a801c831549
  #>
    [CmdletBinding()]

    param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$server,

    [parameter(Mandatory=$false)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [String]$apiKey

    )

    if($server){
        $Global:clusterip=$server
    }
    else{
        $Global:clusterip = read-host "Enter Prism Central Cluster IP"
    }
        
    
    if(!$apiKey){
      if (!$Credential){
              $cred = Get-Credential
              $username = $cred.UserName
              $password = $cred.GetNetworkCredential().Password
      }
      
        $Global:Header = @{
          "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credential.UserName+":"+$credential.GetNetworkCredential().Password))
      }
    }
    if ($apiKey) {
        $Global:Header = @{
            "X-Ntnx-Api-Key" = "$apiKey"
        }
    }
    if(!$header){
        Write-Host "No authentication provided"
        
    }

        
            $APICall = @{
            uri = "https://${clusterip}:9440/api/clustermgmt/v4.0/config/clusters?`$page=$page&`$limit=50"
            Method = 'Get'
            Body = @{
                
            }
            ContentType = "application/json"
            Headers = $Header
            SkipCertificateCheck = $true
            }

            $page_result = ((Invoke-WebRequest @APICall).content | ConvertFrom-Json).data
            if($page_result){
                write-host "Authentication to"$clusterip" was successful"
            }
            if(!$page_result){
              Write-host "Authentication failed"
            }
       
      
}


function New-NTNXAPIKey
{
    <#
    .DESCRIPTION
    This function is used to create a service account within Prism Central and then associate an API key with that service account to use for authentication.

    .PARAMETER RoleName
        Specifies the role in Prism Central you want the service account and API key to be associated with.  Please enter the exact role name as it is specified in Prism Central.

    .PARAMETER ServiceAccountUserName
        Specifies the user name of the service account that will be created.

    .PARAMETER ServiceAccountFirstName
        Specifies the first name of the service account that will be created.

    .PARAMETER ServiceAccountLastName
        Specifies the last name of the service account that will be created.

    .PARAMETER ServiceAccountEmailAddress
        Specifies the email address of the service account that will be created.
    #>
    [CmdletBinding()]

    param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$RoleName,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$ServiceAccountUserName,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$ServiceAccountFirstName,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$ServiceAccountLastName,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$ServiceAccountEmailAddress

    )

    Write-Host "This cmdlet is a work in progress and has not been tested"
    <#
    Powershell script to create a service account and API key for Prism Central v4 API authentication
    Followed the guide here - https://www.nutanix.dev/2025/02/21/nutanix-v4-apis-using-api-key-authentication-part-2/
    #>  

    #Get the role that you wish to use for RBAC on the API user that will be created.  Modify the filter to search for a different role.
    $GetRoles = @{
        uri = "https://${clusterip}:9440/api/iam/v4.0/authz/roles?`$filter=startswith(displayName, '$RoleName')"
        Method = 'Get'
        Body = @{
            
        }
        ContentType = "application/json"
        Headers = $Header
        SkipCertificateCheck = $true
    }

    $RoleExtID = ((Invoke-WebRequest @GetRoles).content | ConvertFrom-Json).data.extId

    #Creates the API service account.  Service accounts can only be created via the API.
    $CreateSVCAccount = @{
        uri = "https://${clusterip}:9440/api/iam/v4.0/authn/users"
        Method = 'Post'
        Body = @"
            {
                "username": "$ServiceAccountUserName",
                "userType": "SERVICE_ACCOUNT",
                "displayName": "API key service account",
                "firstName": "$ServiceAccountFirstName",
                "lastName": "$ServiceAccountLastName",
                "emailId": "$ServiceAccountEmailAddress",
                "status": "ACTIVE",
                "description": "Service account for API key authentication",
                "creationType": "USERDEFINED"
            }
"@

        ContentType = "application/json"
        Headers = $Header
        SkipCertificateCheck = $true
    }

    $userData = ((Invoke-WebRequest @CreateSVCAccount).content | ConvertFrom-Json).data.extId
    if($userData){Write-Host "Service account"$ServiceAccountUserName" created successfully"}
    $userExtId = $userData.extId

    #Creates an API key attached to the previously created service account. The API key will only be displayed once and should be stored securely.
    $CreateAPIKey = @{
        uri = "https://${clusterip}:9440/api/iam/v4.0/authn/users/${userExtId}/keys"
        Method = 'Post'
        Body = @"
            {
                "name": "service_account_api_key",
                "keyType": "API_KEY"
            }
"@

        ContentType = "application/json"
        Headers = $Header
        SkipCertificateCheck = $true
    }

    $apiData = ((Invoke-WebRequest @CreateAPIKey).content | ConvertFrom-Json).Data
    $apiKey = $apiData.KeyDetails.apiKey
    Write-Host "The API key associated with this user is "$apiKey" Please store this API key securely as it will not be shown again."

    #Creates an authorization policy.  Requires the user extId and the group extId from earlier.
    $CreateAuthPolicy = @{
        uri = "https://${clusterip}:9440/api/iam/v4.0/authz/authorization-policies"
        Method = 'Post'
        Body = @"
            {
            "displayName": "API Key Auth Policy",
            "description": "Authorization policy for use with API key service accounts",
            "entities": [
                {
                    "`$reserved": {
                        "*": {
                            "*": {
                                "eq": "*"
                            }
                        }
                    }
                }
            ],   
            "identities": [
                {
                    "`$reserved": {
                        "user": {
                            "uuid": {
                                "anyof": [
                                    "$userExtId"
                                ]
                            }
                        }
                    }
                }
            ],
            "role": "$superExtId"
        }
"@

        ContentType = "application/json"
        Headers = $Header
        SkipCertificateCheck = $true
    }

    $authPolicy = ((Invoke-WebRequest @CreateAuthPolicy).content | ConvertFrom-Json).data



}

function Get-NTNXVMList
{
  <#  
  .DESCRIPTION
   Lists all known AHV VMs

  #>
  $page = 0
  $results = [System.Collections.Generic.List[object]]::new()
  try{

  
  do{
      
          $APICall = @{
          uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms?`$page=$page&`$limit=50"
          Method = 'Get'
          Body = @{
              
          }
          ContentType = "application/json"
          Headers = $Header
          SkipCertificateCheck = $true
          }

          $page_result = ((Invoke-WebRequest @APICall).content | ConvertFrom-Json).data
          if($page_result){
              $results.AddRange($page_result)
          }
      

      $page++

  } until (!$page_result)

  }

  catch {
    <#Do this if a terminating exception happens#>
  }


    $VMs = foreach ($tempVM in $results) {
        New-Object -TypeName PSObject -Property @{
        Name = $tempVM.name
        PowerState = $tempVM.powerState
        Sockets = $tempVM.numSockets
        Cores = $tempVM.numCoresPerSocket
        MemoryGB=$tempVM.memorySizeBytes / 1GB
        extId = $tempVM.extId
        }
    }

    return $VMs | Select-Object Name,PowerState,Sockets,Cores,MemoryGB,extId | Sort-Object -Property Name
}

function Get-NTNXImages
{
  <#  
  .DESCRIPTION
   Lists all disk images managed by Prism Central

  #>
  $page = 0
  $results = [System.Collections.Generic.List[object]]::new()
  do{
      
          $APICall = @{
          uri = "https://${clusterip}:9440/api/vmm/v4.0/content/images?`$page=$page&`$limit=50"
          Method = 'Get'
          Body = @{
              
          }
          ContentType = "application/json"
          Headers = $Header
          SkipCertificateCheck = $true
          }

          $page_result = ((Invoke-WebRequest @APICall).content | ConvertFrom-Json).data
          if($page_result){
              $results.AddRange($page_result)
          }
      

      $page++

  } until (!$page_result)


    $images = foreach ($temp in $results) {
        New-Object -TypeName PSObject -Property @{
        Name = $temp.name
        SizeGB=$temp.sizeBytes / 1GB
        extId = $temp.extId
        }
    }

    return $images | Select-Object Name,SizeGB,extId | Sort-Object -Property Name
}

function Get-NTNXClusters
{
  <#  
  .DESCRIPTION
   Lists all Nutanix clusters managed by Prism Central

  #>
  $page = 0
  $results = [System.Collections.Generic.List[object]]::new()
  do{
      
          $APICall = @{
          uri = "https://${clusterip}:9440/api/clustermgmt/v4.0/config/clusters?`$page=$page&`$limit=50"
          Method = 'Get'
          Body = @{
              
          }
          ContentType = "application/json"
          Headers = $Header
          SkipCertificateCheck = $true
          }

          $page_result = ((Invoke-WebRequest @APICall).content | ConvertFrom-Json).data
          if($page_result){
              $results.AddRange($page_result)
          }
      

      $page++

  } until (!$page_result)

    #Need to figure out a way to filter out the PC cluster
    $clusters = foreach ($temp in $results) {
        New-Object -TypeName PSObject -Property @{
        Name = $temp.name
        VMCount = $temp.VMCount
        NumberOfNodes = $temp.nodes.NumberOfNodes
        Hypervisor = $temp.config.hypervisorTypes
        AOSVersion = $temp.config.buildInfo.version
        ClusterVIP = $temp.network.externalAddress.ipv4.value
        extId = $temp.extId
        }
    }

    return $clusters | Select-Object Name,VMCount,NumberOfNodes,Hypervisor,AOSVersion,ClusterVIP,extId | Sort-Object -Property Name
}

function Get-NTNXSubnets
{
  <#  
  .DESCRIPTION
   Lists all Nutanix subnets managed by Prism Central

  #>
  $page = 0
  $results = [System.Collections.Generic.List[object]]::new()
  do{
      
          $APICall = @{
          uri = "https://${clusterip}:9440/api/networking/v4.0/config/subnets?`$page=$page&`$limit=50"
          Method = 'Get'
          Body = @{
              
          }
          ContentType = "application/json"
          Headers = $Header
          SkipCertificateCheck = $true
          }

          $page_result = ((Invoke-WebRequest @APICall).content | ConvertFrom-Json).data
          if($page_result){
              $results.AddRange($page_result)
          }
      

      $page++

  } until (!$page_result)

    
    $subnets = foreach ($temp in $results) {
        New-Object -TypeName PSObject -Property @{
        Name = $temp.name
        SubnetType = $temp.subnetType
        VLANID = $temp.networkId
        IPAMManaged =  if ($temp.ipConfig){$true}else{$false}
        IPAMStartIP = if ($temp.ipConfig){$temp.ipConfig.ipv4.poolList.startIp.value}
        IPAMEndIP = if ($temp.ipConfig){$temp.ipConfig.ipv4.poolList.startIp.value}
        IPAMDefaultGateway = if ($temp.ipConfig){$temp.ipConfig.ipv4.defaultGatewayIp.value}
        extId = $temp.extId
        }
    }

    return $subnets | Select-Object Name,SubnetType,VLANID,IPAMManaged,IPAMStartIP,IPAMEndIP,IPAMDefaultGateway,extId | Sort-Object -Property Name
}

function Get-NTNXCategories
{
  <#  
  .DESCRIPTION
   Lists all Nutanix categories managed by Prism Central
  #>
    $page = 0
    $results = [System.Collections.Generic.List[object]]::new()
    do{
        

            $APICall = @{
            uri = "https://${clusterip}:9440/api/prism/v4.0/config/categories?`$page=$page&`$limit=50"
            Method = 'Get'
            Body = @{
                
            }
            ContentType = "application/json"
            Headers = $Header
            SkipCertificateCheck = $true
            }

            $page_result = ((Invoke-WebRequest @APICall).content | ConvertFrom-Json).data
            if($page_result){
                $results.AddRange($page_result)
            }
        

        $page++

    } until (!$page_result)
        
        $categories = foreach ($temp in $results) {
            New-Object -TypeName PSObject -Property @{
            Description = $temp.description
            Key = $temp.Key
            Value = $temp.value
            extId = $temp.extId
            }
        }

        return $categories | Select-Object Key,Value,Description,extId | Sort-Object -Property Key
}

function Get-NTNXVM
{
  <#  
  .DESCRIPTION
   Returns the configuration of a specific VM given a string of the name
  #>
  [CmdletBinding()]

    param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$VMname
    )

            $VMextID = (Get-NTNXVMList | Where-Object Name -eq $VMname).extId
    
            $APICall = @{
            uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID"
            Method = 'Get'
            Body = @{
                
            }
            ContentType = "application/json"
            Headers = $Header
            SkipCertificateCheck = $true
            }

            $page_result = ((Invoke-WebRequest @APICall).content | ConvertFrom-Json).data
                    
        return $page_result
}


function New-NTNXVM
{
  <#  
  .DESCRIPTION
   Creates new virtual machines on AHV clusters managed by Prism Central

  #>

  [CmdletBinding()]

    param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$VMname,

    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [String]$VMdescription,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [int]$VMsockets,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [int]$VMcores,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [int]$VMmemoryinGB,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$Cluster,

    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [int]$DiskSizeInGB,

    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [String]$DiskImagetoClone,

    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [String]$VMSubnet,

    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [String]$VMCategory

    )

    Write-Host "This cmdlet is in progress and currently does nothing"


#Example of fully populated VM payload
    $template= @"

{
    "name": "Test VM",
    "description": "Description for your VM",
    "source": {
      "entityType": "VM"
    },
    "numSockets": 24,
    "numCoresPerSocket": 40,
    "numThreadsPerCore": 37,
    "numNumaNodes": 16,
    "memorySizeBytes": 79,
    "isVcpuHardPinningEnabled": false,
    "isCpuPassthroughEnabled": true,
    "enabledCpuFeatures": [
      "HARDWARE_VIRTUALIZATION"
    ],
    "isMemoryOvercommitEnabled": true,
    "isGpuConsoleEnabled": true,
    "isCpuHotplugEnabled": false,
    "isScsiControllerEnabled": false,
    "generationUuid": "574829a1-5b23-4ccc-a6f5-1b573c152d22",
    "biosUuid": "c95aa0dd-c47b-413f-a63c-ed82beee6f1c",
    "categories": [
      {
        "extId": "faa7854f-fc24-444b-a40d-ea56b144c068"
      }
    ],
    "ownershipInfo": {
      "owner": {
        "extId": "820349bc-c59a-46a3-9533-5a29864cec61"
      }
    },
    "host": {
      "extId": "c85c4c2f-c08a-406f-b934-e462ab3f1344"
    },
    "cluster": {
      "extId": "e0bad15c-f9d1-4347-b251-d76d386e82d4"
    },
    "availabilityZone": {
      "extId": "4b0240b7-984e-449a-a5e1-b148bdee5264"
    },
    "guestCustomization": {
      "config": {
        "$objectType": "vmm.v4.ahv.config.Sysprep",
        "installType": "FRESH",
        "sysprepScript": {
          "$objectType": "vmm.v4.ahv.config.Unattendxml",
          "value": "string"
        }
      }
    },
    "guestTools": {
      "isEnabled": true,
      "capabilities": [
        "SELF_SERVICE_RESTORE"
      ]
    },
    "hardwareClockTimezone": "UTC",
    "isBrandingEnabled": false,
    "bootConfig": {
      "$objectType": "vmm.v4.ahv.config.LegacyBoot",
      "bootDevice": {
        "$objectType": "vmm.v4.ahv.config.BootDeviceDisk",
        "diskAddress": {
          "busType": "SCSI",
          "index": 3
        }
      },
      "bootOrder": [
        "CDROM"
      ]
    },
    "isVgaConsoleEnabled": true,
    "machineType": "PC",
    "powerState": "ON",
    "vtpmConfig": {
      "isVtpmEnabled": true
    },
    "isAgentVm": false,
    "apcConfig": {
      "isApcEnabled": true,
      "cpuModel": {
        "extId": "d2bfd9de-700b-4ddf-8c8e-83f63c3565bc",
        "name": "Haswell"
      }
    },
    "storageConfig": {
      "isFlashModeEnabled": true,
      "qosConfig": {
        "throttledIops": 75
      }
    },
    "disks": [
      {
        "diskAddress": {
          "busType": "SCSI",
          "index": 3
        },
        "backingInfo": {
          "$objectType": "vmm.v4.ahv.config.VmDisk",
          "diskSizeBytes": 46,
          "storageContainer": {
            "extId": "c1a39b16-fd62-41d3-b83e-ff006c19cf6e"
          },
          "storageConfig": {
            "isFlashModeEnabled": true
          },
          "dataSource": {
            "reference": {
              "$objectType": "vmm.v4.ahv.config.ImageReference",
              "imageExtId": "2bdbcec9-4333-46c5-a7d1-0b93c9233744"
            }
          }
        }
      }
    ],
    "cdRoms": [
      {
        "diskAddress": {
          "busType": "IDE",
          "index": 94
        },
        "backingInfo": {
          "diskSizeBytes": 46,
          "storageContainer": {
            "extId": "c1a39b16-fd62-41d3-b83e-ff006c19cf6e"
          },
          "storageConfig": {
            "isFlashModeEnabled": true
          },
          "dataSource": {
            "reference": {
              "$objectType": "vmm.v4.ahv.config.ImageReference",
              "imageExtId": "2bdbcec9-4333-46c5-a7d1-0b93c9233744"
            }
          }
        },
        "isoType": "OTHER"
      }
    ],
    "nics": [
      {
        "backingInfo": {
          "model": "VIRTIO",
          "macAddress": "df:8d:df:d8:39:c6",
          "isConnected": true,
          "numQueues": 1
        },
        "networkInfo": {
          "nicType": "NORMAL_NIC",
          "networkFunctionChain": {
            "extId": "493f7732-39dc-411d-8798-864fe3cb44d2"
          },
          "networkFunctionNicType": "INGRESS",
          "subnet": {
            "extId": "28a0f367-14d6-4b0d-a567-ff48b590b156"
          },
          "vlanMode": "ACCESS",
          "trunkedVlans": [
            28
          ],
          "shouldAllowUnknownMacs": false,
          "ipv4Config": {
            "shouldAssignIp": false,
            "ipAddress": {
              "value": "248.218.207.162",
              "prefixLength": 32
            },
            "secondaryIpAddressList": [
              {
                "value": "248.218.207.162",
                "prefixLength": 32
              }
            ]
          },
          "ipv4Info": {}
        }
      }
    ],
    "gpus": [
      {
        "mode": "PASSTHROUGH_GRAPHICS",
        "deviceId": 52,
        "vendor": "NVIDIA",
        "pciAddress": {}
      }
    ],
    "serialPorts": [
      {
        "isConnected": false,
        "index": 3
      }
    ],
    "protectionType": "UNPROTECTED",
    "protectionPolicyState": {
      "policy": {
        "extId": "de17741c-3dc8-449a-9b31-0038687c07d6"
      }
    },
    "pcieDevices": [
      {
        "assignedDeviceInfo": {
          "device": {
            "deviceExtId": "57ea3a89-e6c7-4dd1-b132-9aabc00d13e7"
          }
        },
        "backingInfo": {
          "$objectType": "vmm.v4.ahv.config.PcieDeviceReference",
          "deviceExtId": "57ea3a89-e6c7-4dd1-b132-9aabc00d13e7"
        }
      }
    ]
  }

"@


#Minimum required to create a VM
$minimum= @"

"
{
    "$objectType": "vmm.v4.ahv.config.Vm",
    "cluster": {
        "extId": "0006128f-1b27-63b2-0564-65240d76811e",
        "$objectType": "vmm.v4.ahv.config.ClusterReference"
    }
}
"@


  $VM = @{}
  $VM.add("name",$VMname)
  if($VMdescription){
    $VM.add("description",$VMdescription)
  }
  $VM.add("numSockets",$VMsockets)
  $VM.add("numCoresPerSocket",$VMcores)
  [int]$memory = $VMmemoryinGB*1GB
  $VM.add("memorySizeBytes",$memory)
  #$VM.add("cluster",(Get-NTNXCluster | Where-Object Name -eq $Cluster).extId)
  $list = New-Object System.Collections.ArrayList
  $list.Add(@{"extId"="00061765-d014-8938-0c45-ac1f6b35c712"})
  $clusterObject = @{"cluster"=$list;}
  $VM.add("cluster",$list)
  #think through the category parameter.  Maybe include one key and one value and then search for the extId?
  <#
  if($VMCategory){
    $VM.categories[0].extId = (Get-NTNXCluster | Where-Object Name -eq $VMCategory).extId
  }
  else{
    $VM.categories.clear()   
  }
  
  if($VMSubnet){
    $VM.nics.networkInfo.subnet.extId = (Get-NTNXSubnets | Where-Object Name -eq $VMSubnet).extId
  }
  else{
    $VM.nics.clear()   
  }
  #If an image is present, does diskSizeBytes get cleared?
  if($DiskImagetoClone){
    $VM.disks.backingInfo.dataSource.reference.ImageExtId = (Get-NTNXSubnets | Where-Object Name -eq $DiskImagetoClone).extId
  }
  else{
    $VM.disks.backingInfo.dataSource.reference.ImageExtId.clear()   
  }
  if($DiskSizeInGB){
    $VM.disks.backingInfo.diskSizeBytes = $DiskSizeInGB * 1GB
  }
  else{
    $VM.disks.backingInfo.diskSizeBytes.clear()
  }
  #>

  #Generate a request ID - https://www.nutanix.dev/2022/11/29/using-request-id-headers-with-nutanix-v4-apis/
  $header.add("Ntnx-Request-Id",[System.Guid]::NewGuid().ToString())
        
        $NewVM = @{
            uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms"
            Method = 'Post'
            Body = $VM | ConvertTo-Json
            ContentType = "application/json"
            Headers = $Header
            SkipCertificateCheck = $true
        }
        
        $CreateVM = ((Invoke-WebRequest @NewVM).content | ConvertFrom-Json).data
      
        $header.Remove("Ntnx-Request-Id")

    
}

function Start-NTNXVM
{
  <#  
  .DESCRIPTION
   Powers on a VM given a VM name in string format

  #>

  [CmdletBinding()]

    param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$VMname
    )

    #Get the ExtID of the VM that you're trying to power on
    $VMextID = (Get-NTNXVMList | Where-Object Name -eq $VMname).extId

    #Get that specific VM's configuration so that you can get the eTag in the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
    
      $request = @{
          uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID"
          Method = 'Get'
          Body = @{

          }
          ContentType = "application/json"
          Headers = $Header
          SkipCertificateCheck = $true
      }
      
      $result = Invoke-WebRequest @request
    

      

        $eTag = $result.headers["ETag"]
        #Generate a request ID - https://www.nutanix.dev/2022/11/29/using-request-id-headers-with-nutanix-v4-apis/
        $header.add("Ntnx-Request-Id",[System.Guid]::NewGuid().ToString())
        #Add the eTag to the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
        $header.add('If-match',"$eTag")
        
        $request = @{
            uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID/`$actions/power-on"
            Method = 'Post'
            Body = @{

            }
            ContentType = "application/json"
            Headers = $Header
            SkipCertificateCheck = $true
        }
        
        $result = (Invoke-WebRequest @request -SkipHeaderValidation)

        $header.Remove("Ntnx-Request-Id")
        $header.Remove('If-match')
    
}

function Stop-NTNXVM
{
  <#  
  .DESCRIPTION
   Forcefully stops a VM given a VM name in string format

  #>

  [CmdletBinding()]

    param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$VMname
    )

    #Get the ExtID of the VM that you're trying to power on
    $VMextID = (Get-NTNXVMList | Where-Object Name -eq $VMname).extId

    #Get that specific VM's configuration so that you can get the eTag in the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
    
      $request = @{
          uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID"
          Method = 'Get'
          Body = @{

          }
          ContentType = "application/json"
          Headers = $Header
          SkipCertificateCheck = $true
      }
      
      $result = Invoke-WebRequest @request
    

        $eTag = $result.headers["ETag"]
        #Generate a request ID - https://www.nutanix.dev/2022/11/29/using-request-id-headers-with-nutanix-v4-apis/
        $header.add("Ntnx-Request-Id",[System.Guid]::NewGuid().ToString())
        #Add the eTag to the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
        $header.add('If-match',"$eTag")
        
        $request = @{
            uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID/`$actions/power-off"
            Method = 'Post'
            Body = @{

            }
            ContentType = "application/json"
            Headers = $Header
            SkipCertificateCheck = $true
        }
        
        $result = (Invoke-WebRequest @request -SkipHeaderValidation)
      
        $header.Remove("Ntnx-Request-Id")
        $header.Remove('If-match')
    
}

function Restart-NTNXVM
{
  <#  
  .DESCRIPTION
   Sends a forceful reset of a VM given a VM name in string format

  #>

  [CmdletBinding()]

    param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$VMname
    )

    #Get the ExtID of the VM that you're trying to power on
    $VMextID = (Get-NTNXVMList | Where-Object Name -eq $VMname).extId

    #Get that specific VM's configuration so that you can get the eTag in the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
    
      $request = @{
          uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID"
          Method = 'Get'
          Body = @{

          }
          ContentType = "application/json"
          Headers = $Header
          SkipCertificateCheck = $true
      }
      
      $result = Invoke-WebRequest @request
    

      

        $eTag = $result.headers["ETag"]
        #Generate a request ID - https://www.nutanix.dev/2022/11/29/using-request-id-headers-with-nutanix-v4-apis/
        $header.add("Ntnx-Request-Id",[System.Guid]::NewGuid().ToString())
        #Add the eTag to the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
        $header.add('If-match',"$eTag")
        
        $request = @{
            uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID/`$actions/reset"
            Method = 'Post'
            Body = @{

            }
            ContentType = "application/json"
            Headers = $Header
            SkipCertificateCheck = $true
        }
        
        $result = (Invoke-WebRequest @request -SkipHeaderValidation)
      

        $header.Remove("Ntnx-Request-Id")
        $header.Remove('If-match')
}

function Add-NTNXCategoryToVM
{
  <#  
  .DESCRIPTION
   Sends a forceful reset of a VM given a VM name in string format

  .PARAMETER CategoryKey
    String that specifies the key of the category you wish to add

  .PARAMETER CategoryValue
    String that specifies the value of the category you wish to add

  .PARAMETER VMName
    String that specifies the name of the VM to which you wish to add the category
  #>

  [CmdletBinding()]

    param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$CategoryKey,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$CategoryValue,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$VMname
    )

    #Get the ExtID of the VM that you're trying to power on
    $VMextID = (Get-NTNXVMList | Where-Object Name -eq $VMname).extId
    $Category = Get-NTNXCategories | Where-Object {$_.Key -eq "$CategoryKey" -and $_.Value -eq "$CategoryValue"}
    $Categoryextid = $category.extId

    #Get that specific VM's configuration so that you can get the eTag in the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
    
      $request = @{
          uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID"
          Method = 'Get'
          Body = @{

          }
          ContentType = "application/json"
          Headers = $Header
          SkipCertificateCheck = $true
      }
      
      $result = Invoke-WebRequest @request

        $eTag = $result.headers["ETag"]
        #Generate a request ID - https://www.nutanix.dev/2022/11/29/using-request-id-headers-with-nutanix-v4-apis/
        $header.add("Ntnx-Request-Id",[System.Guid]::NewGuid().ToString())
        #Add the eTag to the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
        $header.add('If-match',"$eTag")
               
        $list = New-Object System.Collections.ArrayList
        $list.Add(@{"extId"="$Categoryextid"})
        $body = @{"categories"=$list;} | ConvertTo-JSON

        $request = @{
            uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID/`$actions/associate-categories"
            Method = 'Post'
            Body = $body
            ContentType = "application/json"
            Headers = $Header
            SkipCertificateCheck = $true
        }
        
        $result = (Invoke-WebRequest @request -SkipHeaderValidation)

        $header.Remove("Ntnx-Request-Id")
        $header.Remove('If-match')
}

function Remove-NTNXCategoryFromVM
{
  <#  
  .DESCRIPTION
   Sends a forceful reset of a VM given a VM name in string format

  .PARAMETER CategoryKey
    String that specifies the key of the category you wish to add

  .PARAMETER CategoryValue
    String that specifies the value of the category you wish to add

  .PARAMETER VMName
    String that specifies the name of the VM to which you wish to add the category
  #>

  [CmdletBinding()]

    param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$CategoryKey,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$CategoryValue,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$VMname
    )

    #Get the ExtID of the VM that you're trying to power on
    $VMextID = (Get-NTNXVMList | Where-Object Name -eq $VMname).extId
    $Category = Get-NTNXCategories | Where-Object {$_.Key -eq "$CategoryKey" -and $_.Value -eq "$CategoryValue"}
    $Categoryextid = $category.extId

    #Get that specific VM's configuration so that you can get the eTag in the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
    
      $request = @{
          uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID"
          Method = 'Get'
          Body = @{

          }
          ContentType = "application/json"
          Headers = $Header
          SkipCertificateCheck = $true
      }
      
      $result = Invoke-WebRequest @request

        $eTag = $result.headers["ETag"]
        #Generate a request ID - https://www.nutanix.dev/2022/11/29/using-request-id-headers-with-nutanix-v4-apis/
        $header.add("Ntnx-Request-Id",[System.Guid]::NewGuid().ToString())
        #Add the eTag to the header - https://www.nutanix.dev/2022/12/01/using-etag-and-if-ne-headers-with-nutanix-v4-apis/
        $header.add('If-match',"$eTag")
               
        $list = New-Object System.Collections.ArrayList
        $list.Add(@{"extId"="$Categoryextid"})
        $body = @{"categories"=$list;} | ConvertTo-JSON

        $request = @{
            uri = "https://${clusterip}:9440/api/vmm/v4.0/ahv/config/vms/$VMextID/`$actions/disassociate-categories"
            Method = 'Post'
            Body = $body
            ContentType = "application/json"
            Headers = $Header
            SkipCertificateCheck = $true
        }
        
        $result = (Invoke-WebRequest @request -SkipHeaderValidation)

        $header.Remove("Ntnx-Request-Id")
        $header.Remove('If-match')
}



