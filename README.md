# Azure-DSC-Template

I setup this repo, as one glorified that deploys the greatest Azure VM, all from **VS Code** & **Azure Resource Manager**.

This uses **NestedTemplates** galore, which starts with the parent **AzureDeploy.json** template.

Basically, this repo:

- Deploys an Azure VM

- Uses the **Custom Script** extension to set **Set-WinSystemLocale -SystemLocale en-AU**. It copies a script from the **artifcats** location to the local C:\ drive to be used as a user logon script (**UserLogonScript.ps1**), then DSC sets up a scheduled task to call the logon script at the time of any user logon (user account context). Finally, the **Custom Script** extension makes changes DSC Local Configuration Manager - this runs as the system account.

    DSC Local Configuration Manager changes are:
    - RefreshFrequencyMins = 30
    - ConfigurationMode = '**ApplyandAutoCorrect**'
    - RebootNodeIfNeeded = $true
    - ActionAfterReboot = 'ContinueConfiguration'
    - ConfigurationModeFrequencyMins = 15

- Uses the new **Microsoft.Resources/resourceGroups** method and creates a resource group in ARM upon deployment, as well as deploys deploys resources to this same Resource Group.

- Makes use of the **Azure Key Vault**, to use both:

    - '**Certificates**' | to install a Private Key Certificate onto the local machine
    - '**Secrets**' | to store the local admin password, and the VNC software key

- Gives you the choice to use either **Un-Managed** disks, or **Managed** disks.

- Gives you the choice to use either an **Existing** vNet, or a **Non-Existing** vNet. It will setup a new vNet if you choose **Non-Existing**.

- Deploys a **vNet** into a separate '**Shared**' Resource Group (Cross Resource Group Deployment), a resource group used for shared resources. The concept being, general Azure resources i.e. a vNet are deployed into separate resource groups.

- Uses the **Copy** element with **Resource iteration**, giving you the choice of how many data disks you want to deploy.

### This Repo:
- Leverages the **DSC extension** to run the configuration on the VM (**DSC\ConfigurationData.ps1**). When running the **DSC extension**, the JSON template also feeds parameter values into this **DSC configuration script** via the DSC extension:

    Parameters being:
    - VM_Name_Suffix
    - nodeName
    - artifactsLocation
    - artifactsLocationSasToken
    - VNCKey

### [My other Repo](https://github.com/marckean/Azure-DSC-Automation):
- Leverages the **DSC extension** only to register the VM with the **Azure Automation** pull server in order for DSC to run the configuration on the VM.

### Deployment:
Simply:
- Clone this repo locally
- Use VS Code, along with the latest Azure PowerShell module
- Change the **AzureDeploy.parameters.json** file
- Run **Deploy-Azure.ps1**

## The below buttons don't work as yet: 

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmarckean%2FAzure-DSC-Template%2Fmaster%2FAzureDeploy.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fmarckean%2FAzure-DSC-Template%2Fmaster%2FAzureDeploy.json" target="_blank">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>
