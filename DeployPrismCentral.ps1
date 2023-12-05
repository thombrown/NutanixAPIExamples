<#
Sample script to deploy an XL Scale out Prism Central to an AOS cluster which already has an existing Prism Central registered and deployed
Version 0.2
Written by Thomas Brown (thomas.brown@nutanix.com)
#>


<#
SCP the 1 click PC bundle and metadata file to /home/nutanix on a CVM then execute
ncli software upload file-path=/home/nutanix/pc.2023.3.tar software-type=prism_central_deploy meta-file-path=/home/nutanix/generated-pc.2023.3-metadata.json
#>

<#
After deploying PC, you need to SSH to PC as nutanix and change the admin password by executing
ncli user reset-password user-name=admin password=yyyyy
#>

<#
PC Sizes for my reference
Small = 6 vCPU, 26GB RAM
Large = 10 vCPU, 44GB RAM
XL = 14 vCPU, 60GB RAM
#>

#Enter login info
$clusterip = read-host "Enter Prism Element Cluster IP"
$creds = Get-Credential

#Which endpoint you are trying to hit
$Uri = "https://${clusterip}:9440/api/nutanix/v3/prism_central"

#Pass the credentials in the header
$Header = @{
    "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($creds.UserName+":"+$creds.GetNetworkCredential().Password))
}

#Make sure to update the storage container and network UUIDs prior to sending this

#Build the body of the request
$body = @"
{
    "resources": {
        "pc_vm_list": [
            {
                "vm_name": "PC-Scaleout-1",
                "container_uuid": "ab575649-b9ff-44b4-ad4c-02aef99555c2",
                "num_sockets": 14,
                "data_disk_size_bytes": 2684354560000,
                "memory_size_bytes": 64424509440,
                "nic_list": [
                    {
                        "ip_list": [
                            "10.38.55.51"
                        ],
                        "network_configuration": {
                            "network_uuid": "ab1e9c8b-cf84-4752-8c29-64519eaf2ad8",
                            "subnet_mask": "255.255.255.128",
                            "default_gateway": "10.38.55.1"
                        }
                    }
                ],
                "dns_server_ip_list": [
                    "10.42.194.10"
                ],
                "ntp_server_list": [
                    "10.42.194.10"
                ]
            },
            {
                "vm_name": "PC-Scaleout-2",
                "container_uuid": "ab575649-b9ff-44b4-ad4c-02aef99555c2",
                "num_sockets": 14,
                "data_disk_size_bytes": 2684354560000,
                "memory_size_bytes": 64424509440,
                "nic_list": [
                    {
                        "ip_list": [
                            "10.38.55.52"
                        ],
                        "network_configuration": {
                            "network_uuid": "ab1e9c8b-cf84-4752-8c29-64519eaf2ad8",
                            "subnet_mask": "255.255.255.128",
                            "default_gateway": "10.38.55.1"
                        }
                    }
                ],
                "dns_server_ip_list": [
                    "10.42.194.10"
                ],
                "ntp_server_list": [
                    "10.42.194.10"
                ]
            },
            {
                "vm_name": "PC-Scaleout-3",
                "container_uuid": "ab575649-b9ff-44b4-ad4c-02aef99555c2",
                "num_sockets": 14,
                "data_disk_size_bytes": 2684354560000,
                "memory_size_bytes": 64424509440,
                "nic_list": [
                    {
                        "ip_list": [
                            "10.38.55.53"
                        ],
                        "network_configuration": {
                            "network_uuid": "ab1e9c8b-cf84-4752-8c29-64519eaf2ad8",
                            "subnet_mask": "255.255.255.128",
                            "default_gateway": "10.38.55.1"
                        }
                    }
                ],
                "dns_server_ip_list": [
                    "10.42.194.10"
                ],
                "ntp_server_list": [
                    "10.42.194.10"
                ]
            }
        ],
        "cmsp_config": {
            "platform_network_configuration": {
                "subnet_mask": "255.255.255.0",
                "type": "kPrivateNetwork",
                "default_gateway": "192.168.5.1"
            },
            "pc_domain_name": "prism-central.cluster.local",
            "platform_ip_block_list": [
                "192.168.5.2 192.168.5.64"
            ]
        },
        "version": "pc.2023.3",
        "should_auto_register": false,
        "virtual_ip": "10.38.55.50"
    }
}

"@

#Here is the actual API request. If using Powershell v6 or higher with a self signed certificate on Prism Central, use -SkipCertificateCheck on the end of the command
$response = Invoke-WebRequest -Method Post -Uri $Uri -Headers $Header -ContentType "application/json" -Body $body -SkipCertificateCheck
