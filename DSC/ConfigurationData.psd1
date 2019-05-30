#region Environment Configuration
<#
Configuring the Local Configuration Manager
https://docs.microsoft.com/en-us/powershell/dsc/metaconfig
#>
@{ 
    # Node specific data 
    AllNodes = @( 
       @{ 
            NodeName = '*'
            BuildData = "$env:SystemDrive\SourceFiles"
            #TimeZone = 'GMT Standard Time'
            #LocalAdministrators = 'MyLocalUser'
       },
       @{
            NodeName = 'Server1'
            #Role = 'Primary'
       },
       @{
            NodeName = 'Server2'
            #Role = 'Secondary'
       }
    );
} 
#endregion