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
            PsDscAllowPlainTextPassword = $true
       }
    );
} 
#endregion