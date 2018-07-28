# Azure-DSC-Template

Details here https://marckean.com/2018/07/24/azure-dsc-deployment-using-a-json-template/

Basically

- Deploys an Azure VM
- Deploys a vNet into a separate Resource Group (Cross Resource Group Deployment), a resource group used for shared resources
- Leverages the Custom Script extension which runs a script as the local computer account at the time of deployment. This script copies a script from the artifcats location to the local C:\ drive to be used as a user logon script. The DSC sets up a scheduled task to call the script at the time of any user logon.

### This Repo:
- leverages the DSC extension to run the configuration on the VM. The JSON template also feeds parameter values into a DSC configuration script via the DSC extension

### [My other Repo](https://github.com/marckean/Azure-DSC-Automation)
- Leverages the DSC extension only to register the VM with the Azure Automation pull server in order for DSC to run the configuration on the VM.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmarckean%2FAzure-DSC-Template%2Fmaster%2FWindowsVirtualMachine.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fmarckean%2FAzure-DSC-Template%2Fmaster%2FWindowsVirtualMachine.json" target="_blank">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>
