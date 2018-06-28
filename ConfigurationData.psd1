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
            #ConfigurationID = "646e48cb-3082-4a12-9fd9-f71b9a562d4e"
            #DownloadManagerName = "WebDownloadManager"
            #DownloadManagerCustomData = (@{ServerUrl="https://$PullService/psdscpullserver.svc"})
            #CertificateFile = 'C:\publickey.cer'
            #CertificateID = "71AA68562316FE3F73536F1096B85D66289ED60E"
            #Credential = $cred
            #AllowModuleOverwrite = $false
       }
    );
}  
#endregion
#
