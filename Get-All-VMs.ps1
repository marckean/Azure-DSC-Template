<#
.SYNOPSIS
    Script that displays all VM's (both Classic and Resource Manager) in all
    subscriptions
.DESCRIPTION
    The running/stopped status of all VM's will be displayed using objects in
    an array. This script gets both classic and resource manager VM's and
    get their properties. These are different commands and the commands have
    different output. To get VM's in a specific resource mode subscription, it
    is actually neccesary to use Login-AzureRMAccount per subscription, it is
    not sufficient to use Select-AzureSubscirption

    The following properties are displayed for each VM:
    SubscriptionName, PortalVersion, Name, Status, Size

    If neccesary output can be limited to one subscription only

.NOTES
    File Name      : get-all-vms-in-all-subscriptions.ps1
    Author         : J.Schipper (J.Schipper@uu.nl)
    Prerequisite   : PowerShell with Azure module
    (C) Copyright 2015 - J.Schipper
.LINK
.EXAMPLE
    get-all-vms-in-all-subscriptions.ps1 # All VM's in all subscriptions
    get-all-vms-in-all-subscriptions.ps1 -SubscriptionName MySubscription
#>

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False)]
   [string]$SubscriptionName,
	
   [Parameter(Mandatory=$False)]
   [string]$SubscriptionId

)

# Comment out if module not imported
Import-Module Azure
$cred = Get-Credential

(Login-AzureRmAccount -Credential $cred)>0

# Get Publish file (not needed every time)
# Get-AzurePublishSettingsFile

# Replace FILENAME with your file
# (Import-AzurePublishSettingsFile "FILENAME")>0

$Subscriptions = Get-Azuresubscription

if ($SubscriptionName)
{
    $Subscriptions = $Subscriptions | where { $_.SubscriptionName -EQ $SubscriptionName }
}
elseif ($SubscriptionId)
{
    $Subscriptions = $Subscriptions | where { $_.SubscriptionId -EQ $SubscriptionId }
}

$vmarray = @()
$i=0

foreach ( $Subscription in $Subscriptions ) {

    $SubscriptionId = $Subscription.SubscriptionId

    (Login-AzureRmAccount -Credential $cred -subscriptionid $SubscriptionId)>0

    (Select-AzureSubscription -current -SubscriptionId $SubscriptionId)>0

    # Display progress, this script may take a while
    $i++
    Write-Progress -activity $subscription.SubscriptionName -PercentComplete ($i/$Subscriptions.Count*100)

    # Get all of the VM's:
    ($rmvms=Get-AzurermVM) > 0
    ($smvms=Get-AzureVM) > 0

    # Add info about VM's from the Resource Manager to the array
    foreach ($vm in $rmvms)
    {    
        # Get status (does not seem to be a property of $vm, so need to call Get-AzurevmVM for each rmVM)
        $vmstatus = Get-AzurermVM -Name $vm.Name -ResourceGroupName $vm.ResourceGroupName -Status 

        # Add values to the array:
        $vmarray += New-Object PSObject -Property @{`
            Subscription=$Subscription.SubscriptionName; `
            AzureMode="Resource_Manager"; `
            Name=$vm.Name; PowerState=(get-culture).TextInfo.ToTitleCase(($vmstatus.statuses)[1].code.split("/")[1]); `
            Size=$vm.HardwareProfile.VirtualMachineSize}
    }

    # Add info about the Service Manager VM's to the array
    foreach ($vm in $smvms)
    {
        $vmarray += New-Object PSObject -Property @{`
            Subscription=$Subscription.SubscriptionName;`
            AzureMode="Service_Manager";`
            Name=$vm.InstanceName;`
            PowerState=$vm.PowerState;`
            Size=$vm.InstanceSize}
    }

}

# Choose your output:
# $vmarray
$vmarray | ft
# $vmarray | Out-Gridview
