#Requires -Version 3.0
#Requires -Module AzureRM.Resources
#Requires -Module Azure.Storage
#Requires -Module @{ModuleName="AzureRm.Profile";ModuleVersion="3.0"}

# Login to Azure with a Service Principal
# Create an AAD Service Principal | https://docs.microsoft.com/en-us/cli/azure/create-an-azure-service-principal-azure-cli
$SubscriptionId = '6bb00255-5486-4db1-96ca-5baefc18b0b2'
$AADAppId = 'ea77ac17-5785-419b-a198-aaa384421905' # 201809MarcKeanSP_CLI
$securePass = Read-Host "Azure password: " -AsSecureString
$TenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47' # microsoft.onmicrosoft.com
$Cred = New-Object System.Management.Automation.PSCredential ($AADAppId, $securePass)
Connect-AzureRmAccount -Credential $cred -ServicePrincipal -TenantId $TenantId

Select-AzureRmSubscription -SubscriptionId $SubscriptionId

$ArtifactStagingDirectory = '.'
$TemplateParametersFile = $ArtifactStagingDirectory + '\AzureDeploy.parameters.json'
$ResourceGroupLocation = 'australiaeast'
$UploadArtifacts = 'true'
# Pull RG_Name from parameters file
$ResourceGroupName = (Get-Content $TemplateParametersFile -Raw | ConvertFrom-Json).parameters.RG_Name.Value
$StorageContainerName = $ResourceGroupName.ToLowerInvariant() + '-stageartifacts'
$TemplateFile = $ArtifactStagingDirectory + '\AzureDeploy.json'
$DSCSourceFolder = $ArtifactStagingDirectory + '\DSC'
$DebugOptions = "None"
$StorageAccountName = 'stage' + ((Get-AzureRmContext).Subscription.Id).Replace('-', '').substring(0, 19)

try {
    [Microsoft.Azure.Common.Authentication.AzureSession]::ClientFactory.AddUserAgent("AzureQuickStarts-$UI$($host.name)".replace(" ","_"), "1.0")
} catch { }

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

function Format-ValidationOutput {
    param ($ValidationOutput, [int] $Depth = 0)
    Set-StrictMode -Off
    return @($ValidationOutput | Where-Object { $_ -ne $null } | ForEach-Object { @('  ' * $Depth + ': ' + $_.Message) + @(Format-ValidationOutput @($_.Details) ($Depth + 1)) })
}

$OptionalParameters = New-Object -TypeName Hashtable
$TemplateArgs = New-Object -TypeName Hashtable

Write-Host "Using parameter file: $TemplateParametersFile"

if ($UploadArtifacts) {
   
    # Parse the parameter file and update the values of artifacts location and artifacts location SAS token if they are present
    $JsonParameters = Get-Content $TemplateParametersFile -Raw | ConvertFrom-Json
    if (($JsonParameters | Get-Member -Type NoteProperty 'parameters') -ne $null) {
        $JsonParameters = $JsonParameters.parameters
    }
    $ArtifactsLocationName = '_artifactsLocation'
    $ArtifactsLocationSasTokenName = '_artifactsLocationSasToken'
    $OptionalParameters[$ArtifactsLocationName] = $JsonParameters | Select-Object -Expand $ArtifactsLocationName -ErrorAction Ignore | Select-Object -Expand 'value' -ErrorAction Ignore
    $OptionalParameters[$ArtifactsLocationSasTokenName] = $JsonParameters | Select-Object -Expand $ArtifactsLocationSasTokenName -ErrorAction Ignore | Select-Object -Expand 'value' -ErrorAction Ignore

    # Create DSC configuration archive
    if (Test-Path $DSCSourceFolder) {
        $DSCSourceFilePaths = @(Get-ChildItem $DSCSourceFolder -File -Filter '*.ps1' | ForEach-Object -Process {$_.FullName})
        foreach ($DSCSourceFilePath in $DSCSourceFilePaths) {
            $DSCArchiveFilePath = $DSCSourceFilePath.Substring(0, $DSCSourceFilePath.Length - 4) + '.zip'
            Publish-AzureRmVMDscConfiguration $DSCSourceFilePath -OutputArchivePath $DSCArchiveFilePath -Force -Verbose
            #Publish-AzureRmVMDscConfiguration $DSCSourceFilePath -OutputArchivePath $DSCArchiveFilePath -AdditionalPath ($DSCSourceFolder  + '\xPSDesiredStateConfiguration') -Force -Verbose
        }
    }

     $StorageAccount = (Get-AzureRmStorageAccount | Where-Object{$_.StorageAccountName -eq $StorageAccountName})

    # Create the storage account if it doesn't already exist
    if ($StorageAccount -eq $null) {
        $StorageResourceGroupName = 'ARM_Deploy_Staging'
        New-AzureRmResourceGroup -Location "$ResourceGroupLocation" -Name $StorageResourceGroupName -Force
        $StorageAccount = New-AzureRmStorageAccount -StorageAccountName $StorageAccountName -Type 'Standard_LRS' -ResourceGroupName $StorageResourceGroupName -Location "$ResourceGroupLocation"
    }

    # Generate the value for artifacts location if it is not provided in the parameter file
    if ($OptionalParameters[$ArtifactsLocationName] -eq $null) {
        $OptionalParameters[$ArtifactsLocationName] = $StorageAccount.Context.BlobEndPoint + $StorageContainerName + "/"
    }

    # Copy files from the local storage staging location to the storage account container
    New-AzureStorageContainer -Name $StorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1

    $ArtifactFilePaths = Get-ChildItem $ArtifactStagingDirectory -Recurse -File | ForEach-Object -Process {$_.FullName}
    foreach ($SourcePath in $ArtifactFilePaths) {
       Set-AzureStorageBlobContent -File $SourcePath -Blob $SourcePath.Substring(((Get-Location).Path).length + 1) -Container $StorageContainerName -Context $StorageAccount.Context -Force       
    }
    # Generate a 4 hour SAS token for the artifacts location if one was not provided in the parameters file
    if ($OptionalParameters[$ArtifactsLocationSasTokenName] -eq $null) {
        $OptionalParameters[$ArtifactsLocationSasTokenName] = (New-AzureStorageContainerSASToken -Container $StorageContainerName -Context $StorageAccount.Context -Permission r -ExpiryTime (Get-Date).AddHours(4))
    }

    # Add the Template file full URI including the SAS token as a TemplateFile Key to the $TemplateArgs hash table
    $TemplateArgs.Add('TemplateFile', $OptionalParameters[$ArtifactsLocationName] + (Get-ChildItem $TemplateFile).Name + $OptionalParameters[$ArtifactsLocationSasTokenName])
    
}
else {

    $TemplateArgs.Add('TemplateFile', $TemplateFile)

}

$TemplateArgs.Add('TemplateParameterFile', $TemplateParametersFile)

New-AzureRmDeployment -Name ((Get-ChildItem $TemplateFile).BaseName + '-' + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmmss')) `
                      -Location 'Australia East' `
                      @TemplateArgs `
                      @OptionalParameters `
                      -Verbose `
                      -ErrorVariable ErrorMessages

if ($ErrorMessages) {
Write-Output '', 'Template deployment returned the following errors:', @(@($ErrorMessages) | ForEach-Object { $_.Exception.Message.TrimEnd("`r`n") })
}
