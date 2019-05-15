# Certificate you need for encrypting passwords
# ... Securing the MOF File - https://docs.microsoft.com/en-us/powershell/dsc/securemof

# Set Debug from 'SilentlyContinue' to 'Continue'
$DebugPreference = 'Continue'

#region Node Configuration (Main)
configuration Main
{
param
(
[string]$VM_Name_Suffix = "localhost",
[string]$nodeName = $env:COMPUTERNAME,
[string]$dscartifacts,
[string]$dscartifactsSasToken,
[string]$VNCKey,
[PSCredential]$eJukebox_credential,
[PSCredential]$eJukeboxTask_credential,
[PSCredential]$ejukeboxScrpsAcces_credential,
[PSCredential]$ejukeboxAppPool_credential
)

Import-DscResource -ModuleName PSDesiredStateConfiguration
Import-DscResource -ModuleName xWebAdministration

$BuildData = "$env:SystemDrive\SourceFiles"
Node $env:COMPUTERNAME
  {

LocalConfigurationManager
{
    CertificateId = $node.Thumbprint
}

################################################################################
##################     Files & Directories
################################################################################
#region Files and Directories
    File BuildData
    {
        DestinationPath = $BuildData
        Ensure = 'Present'
        Type = 'Directory'
    }
    File AzCopy
    {
        DestinationPath = $BuildData + '\AzCopy'
        Ensure = 'Present'
        Type = 'Directory'
    }
    File StationPlaylistData {
        SourcePath = "$BuildData\ejukeartifacts\StationPlaylist\Data"
        DestinationPath = "${env:ProgramFiles(x86)}\StationPlaylist\Data"
        Ensure = 'Present'
        Type = 'Directory'
        Recurse = $true
        DependsOn = "[Script]StationPlaylistInstall"
      }
      File PHPFiles {
        SourcePath = "$BuildData\ejukeartifacts\PHP\PHP-7.0.13"
        DestinationPath = "$env:SystemDrive\PHP\7.0.13"
        Ensure = 'Present'
        Type = 'Directory'
        Recurse = $true
        DependsOn = "[Script]CopyeJukeboxBuildFiles"
      }
    File WinCache {
        SourcePath = "$BuildData\ejukeartifacts\PHP\WinCache 2.0.0.8\php_wincache.dll"
        DestinationPath = "$env:SystemDrive\PHP\7.0.13\ext"
        Ensure = 'Present'
        Type = 'File'
        DependsOn = "[File]PHPFiles"
      }
    File SC_Serv {
        SourcePath = "$BuildData\ejukeartifacts\ShoutCast\sc_serv.conf"
        DestinationPath = "$env:ProgramFiles\SHOUTcast"
        Ensure = 'Present'
        Type = 'File'
        DependsOn = "[Script]SHOUTcastInstall"
      }
#endregion

################################################################################
##################     Packages
################################################################################
#region Packages
    Package InstallVNCServer
    {
        Ensure = "Present"
        Path = "$BuildData\ejukeartifacts\VNC\VNC-Server-5.3.2-Windows-en-64bit.msi"
        Name = "VNC Server 5.3.2"
        ProductId = "{BD3BF59A-3CD6-49B3-A166-E57BF55FF959}"
        #Arguments = "ADDLOCAL=ALL"
        DependsOn = "[Script]CopyeJukeboxBuildFiles"
    }
    Package PHPManagerForIIS
    { 
        Ensure = "Present"
        Path = "$BuildData\ejukeartifacts\PHP\PHP Manager 1.4.0\PHPManagerForIIS-1.4.0-x64.msi"
        ProductId = "{E851486F-1FE2-44F0-85ED-F969088A68EE}"
        Name = "PHP Manager 1.4 for IIS 10"
        DependsOn = "[Script]CopyeJukeboxBuildFiles"
    }
#endregion

################################################################################
##################     Windows Features
################################################################################
#region Windows Features
    foreach ($Feature in @("Web-Server","Web-Common-Http","Web-Static-Content", ` 
            "Web-Default-Doc","Web-Dir-Browsing","Web-Http-Errors",` 
            "Web-Health","Web-Http-Logging","Web-Log-Libraries",` 
            "Web-Request-Monitor","Web-Security","Web-Filtering",`
            "Web-Stat-Compression","Web-Http-Redirect","Web-Mgmt-Tools",`
            "WAS","WAS-Process-Model","WAS-NET-Environment","WAS-Config-APIs","Web-CGI"))
        {
    WindowsFeature $Feature
    {
      Name = $Feature
      Ensure = "Present"
    }
}
#endregion

################################################################################
##################     Scripts
################################################################################
#region Scripts
    Script DownloadAzCopy
    {
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            Test-Path "$using:BuildData\ejukeartifacts\AzCopy\AzCopy.exe"
        }
        SetScript = {
            $source = "https://ejukebox03.blob.core.windows.net/deployment/AzCopy/azcopy.exe"
            $dest = "$using:BuildData\ejukeartifacts\AzCopy\AzCopy.exe"
            Invoke-WebRequest $source -OutFile $dest
        }
		GetScript = { # should return a hashtable representing the state of the current node
            $result = Test-Path "$using:BuildData\ejukeartifacts\AzCopy\AzCopy.exe"
			@{
				"Downloaded" = $result
			}
		}
        DependsOn = "[File]AzCopy"
    }
    Script CopyeJukeboxBuildFiles # Using the new AzCopy v10 using a SAS token
    {
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            Test-Path "$using:builddata\ejukeartifacts\StationPlaylist"
        }
        SetScript = {
            $prog = "$using:BuildData\ejukeartifacts\AzCopy\AzCopy.exe"
            $params = '{0} {5}{1}{2}{5} {5}{3}{5} {4}' -f 'copy', $using:dscartifacts, $using:dscartifactsSasToken, 'C:\SourceFiles', '--overwrite=false --recursive=true', '"'
            Start-Process $prog $params -Wait

        }
		GetScript = { # should return a hashtable representing the state of the current node
            $result = Test-Path "$using:builddata\ejukeartifacts\StationPlaylist"
			@{
				"Downloaded" = $result
			}
		}
        DependsOn = "[Script]DownloadAzCopy"
    }
    # StationPlaylist Install
	Script StationPlaylistInstall
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            Test-Path "${env:ProgramFiles(x86)}\StationPlaylist\Studio\SPLStudio.exe"
        }
        SetScript = {
            $process = "$using:BuildData\ejukeartifacts\StationPlaylist\StudioSetup531.exe"
			$arguments = '/silent /norestart /closeapplications /restartapplications'
			start-process $process -ArgumentList $arguments -Wait

        }
		GetScript = { # should return a hashtable representing the state of the current node
        $result = Test-Path "${env:ProgramFiles(x86)}\StationPlaylist\Studio\SPLStudio.exe"
			@{
				"Installed" = $result
			}
		}
        DependsOn = "[Script]CopyeJukeboxBuildFiles" 
    }   
	# Disable Password Complexity
    Script DisablePasswordComplexity
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            $null = secedit /export /cfg $env:USERPROFILE\secpol.cfg
			$null = (Get-Content $env:USERPROFILE\secpol.cfg) | ? {$_ -match 'PasswordComplexity.=.(.)'}
			$null = Remove-Item -force $env:USERPROFILE\secpol.cfg -confirm:$false
			# make sure PasswordComplexity is set to '0'
			$Matches[1] -eq '0'
        }
        SetScript = {
            # Disable Password Complexity
			secedit /export /cfg $env:USERPROFILE\secpol.cfg
			(gc $env:USERPROFILE\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File $env:USERPROFILE\secpol.cfg
			secedit /configure /db c:\windows\security\local.sdb /cfg $env:USERPROFILE\secpol.cfg /areas SECURITYPOLICY
			Remove-Item -force $env:USERPROFILE\secpol.cfg -confirm:$false
        }
		GetScript = { # should return a hashtable representing the state of the current node
            $null = secedit /export /cfg $env:USERPROFILE\secpol.cfg
			$null = (Get-Content $env:USERPROFILE\secpol.cfg) | ? {$_ -match 'PasswordComplexity.=.(.)'}
			$null = Remove-Item -force $env:USERPROFILE\secpol.cfg -confirm:$false
			
			@{
				"PasswordComplexity" = $Matches[1]
			}
		}
    }
    # Configure VNC Server
	Script ConfigureVNCServer
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            if ((Get-ItemProperty -Path 'HKLM:\Software\RealVNC\vncserver' -ErrorAction SilentlyContinue).Password -eq '0db038a948f57c87f7e4608295c6ea23') {return $True}
			else {return $False}
        }
        SetScript = {
            $process = "$env:ProgramFiles\RealVNC\VNC Server\vnclicense.exe"
			$arguments = "-add $($using:VNCkey)"
			start-process $process -ArgumentList $arguments -Wait

			New-ItemProperty -Path 'HKLM:\Software\RealVNC\vncserver' -Name 'Authentication' -Value 'VncAuth' -Force
			New-ItemProperty -Path 'HKLM:\Software\RealVNC\vncserver' -Name 'CaptureMethod' -Value '0' -Force
			New-ItemProperty -Path 'HKLM:\Software\RealVNC\vncserver' -Name 'EnableAutoUpdateChecks' -Value '0' -Force
			New-ItemProperty -Path 'HKLM:\Software\RealVNC\vncserver' -Name 'Encryption' -Value 'AlwaysOn' -Force
			New-ItemProperty -Path 'HKLM:\Software\RealVNC\vncserver' -Name 'HttpPort' -Value '5190' -Force
			New-ItemProperty -Path 'HKLM:\Software\RealVNC\vncserver' -Name 'Password' -Value 'facbcf50c3bf1c08' -Force # Passw0rd
			New-ItemProperty -Path 'HKLM:\Software\RealVNC\vncserver' -Name 'RfbPort' -Value '5190' -Force
			New-ItemProperty -Path 'HKLM:\Software\RealVNC\vncserver' -Name 'UserPasswdVerifier' -Value 'VncAuth' -Force

			Restart-Service -Name vncserver -Force
        }
		GetScript = { # should return a hashtable representing the state of the current node
        $result = Test-Path -Path "$env:ProgramFiles\RealVNC\VNC Server\vncserver.exe"
			@{
				"Installed" = $result
			}
		}
		DependsOn = "[Package]InstallVNCServer"
    }

    # Map M Drive & Start Studio Scheduled Task
    Script UserLogonScript
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            if (Get-ScheduledTask -TaskName "UserLogonScript" -ErrorAction SilentlyContinue) {return $True}
			else {return $False}
        }
        SetScript = {
			# M-Drive & StationPlaylist Studio ScheduledTask
            # This will create a scheduled task which will run a UserLogonScript for any user that logs on changing the regional settings for the user to Australia.
            $ShedService = New-Object -comobject 'Schedule.Service'
            $ShedService.Connect()

            $Task = $ShedService.NewTask(0)
            $Task.RegistrationInfo.Description = 'UserLogonScript'
            $Task.Settings.Enabled = $true
            $Task.Settings.AllowDemandStart = $true

            $trigger = $task.triggers.Create(9)
            $trigger.Enabled = $true

            $action = $Task.Actions.Create(0)
            $action.Path = 'PowerShell.exe'
            $action.Arguments = '-ExecutionPolicy Unrestricted -File c:\UserLogonScript.ps1'
            # $action.WorkingDirectory = ''

            $taskFolder = $ShedService.GetFolder("\")
            $taskFolder.RegisterTaskDefinition('UserLogonScript', $Task , 6, 'Users', $null, 4)
        }
		GetScript = { # should return a hashtable representing the state of the current node
            if (Get-ScheduledTask -TaskName "UserLogonScript" -ErrorAction SilentlyContinue) {return $True}
			else {$result = $False}
			@{
				"ScheduledTaskExists" = $result
			}
		}
    }
    # SHOUTcast Install
	Script SHOUTcastInstall
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            Test-Path "$env:ProgramFiles\SHOUTcast\sc_serv.exe"
        }
        SetScript = {
            $process = "$using:BuildData\ejukeartifacts\ShoutCast\sc_serv2_win64-latest.exe"
			$arguments = '/S'
			start-process $process -ArgumentList $arguments -Wait

        }
		GetScript = { # should return a hashtable representing the state of the current node
        $result = Test-Path "$env:ProgramFiles\SHOUTcast\sc_serv.exe"
			@{
				"Installed" = $result
			}
		}
        DependsOn = "[Script]CopyeJukeboxBuildFiles" 
    }
	# SHOUTcast as a Windows Service
	Script SHOUTcastService
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            if (Get-Service -Name Shoutcast -ErrorAction SilentlyContinue) {return $True}
			else {return $False}
        }
        SetScript = {
            $process = "$env:ProgramFiles\SHOUTcast\sc_serv.exe"
			$arguments = 'install Shoutcast sc_serv.conf'
			start-process $process -ArgumentList $arguments -Wait

        }
		GetScript = { # should return a hashtable representing the state of the current node
        if (Get-Service -Name Shoutcast -ErrorAction SilentlyContinue) {$result = $True}
			else {$result = $False}
			@{
				"Installed" = $result
			}
		}
        DependsOn = "[Script]SHOUTcastInstall" 
    }
	# Visual C++ Redistributable for Visual Studio 2015 x64 Install
	Script vcRedistInstall
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            $Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{FDBE9DB4-7A91-3A28-B27E-705EF7CFAE57}'
            Test-Path $Key
        }
        SetScript = {

            $process = "$env:SystemDrive\eJukeboxBuild\PHP\Visual CPlus_Plus Redistributable for Visual Studio 2015 x64\vc_redist.x64.exe"
			$arguments = '/install /quiet /norestart'
			start-process $process -ArgumentList $arguments -Wait

        }
		GetScript = { # should return a hashtable representing the state of the current node
            $Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{FDBE9DB4-7A91-3A28-B27E-705EF7CFAE57}'
			@{
				"Installed" = (Test-Path $Key)
			}
		}
        DependsOn = "[Script]CopyeJukeboxBuildFiles"     
    }
    # Set ACLs for PHP for IIS to process it appropriately
	Script PHPACLs
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            $php_install = "$env:SystemDrive\php"
            $PHPInstallACLs = ((Get-Acl $php_install).Access.IdentityReference)
            $result = $false

            $PHPInstallACLs | % {if($_.Value -eq 'IIS APPPOOL\DefaultAppPool'){$result = $True}}
            return $result
        }
        SetScript = {
            $php_install = "$env:SystemDrive\php"
            
            $acl = get-acl $php_install
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("IIS AppPool\DefaultAppPool", "ReadAndExecute", "ContainerInherit, ObjectInherit", "None","Allow")
            $acl.setaccessrule($ar)
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users", "ReadAndExecute", "ContainerInherit, ObjectInherit", "None","Allow")
            $acl.setaccessrule($ar)
            set-acl $php_install $acl

            $php_log = "c:\phplog"

            if ((Test-Path -path $php_log) -ne $True) {
            new-item -type directory -path $php_log}
            $acl = get-acl $php_log
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users","Modify","Allow")
            $acl.setaccessrule($ar)
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("IIS AppPool\DefaultAppPool", "Modify", "ContainerInherit, ObjectInherit", "None","Allow")
            $acl.setaccessrule($ar)
            set-acl $php_log $acl
            
            $php_temp = "c:\phptemp"

            if ((Test-Path -path $php_temp) -ne $True) {
            new-item -type directory -path $php_temp}
            $acl = get-acl $php_temp
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users","Modify","Allow")
            $acl.setaccessrule($ar)
            $ar = new-object system.security.accesscontrol.filesystemaccessrule("IIS AppPool\DefaultAppPool", "Modify", "ContainerInherit, ObjectInherit", "None","Allow")
            $acl.setaccessrule($ar)
            set-acl $php_temp $acl

        }
		GetScript = { # should return a hashtable representing the state of the current node
            $php_install = "$env:SystemDrive\php"
            $PHPInstallACLs = ((Get-Acl $php_install).Access.IdentityReference)
            $result = $false

            $PHPInstallACLs | % {if($_.Value -eq 'IIS APPPOOL\DefaultAppPool'){$result = $True}}
			@{
				"PHPACLsConfigured" = $result
			}
		}
        DependsOn = "[File]PHPFiles"
    }
	# Configure PHP for IIS
	Script ConfigurePHP
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            $result = $true
            if ( (Get-PSSnapin -Name PHPManagerSnapin -ErrorAction SilentlyContinue) -eq $null )
            {
                $result = $false 
            }

            return $result
        }
        SetScript = {
            $php_install = "$env:SystemDrive\php"
            $php_version = '7.0.13'
            $php_log = "$env:SystemDrive\phplog"
            $php_temp = "$env:SystemDrive\phptemp"
            $web_root = "$env:SystemDrive\inetpub\wwwroot"
            $web_log = "$env:SystemDrive\wwwlogs"

            Add-PsSnapin PHPManagerSnapin
            Rename-Item -Path "$php_install\$php_version\php.ini-production" -NewName "$php_install\$php_version\php.ini" -ErrorAction SilentlyContinue
            New-PHPVersion -ScriptProcessor "$php_install\$php_version\php-cgi.exe"
            #Configure Home Office Settings
            Set-PHPSetting -name date.timezone -value "Australia/Sydney"
            Set-PHPSetting -name upload_max_filesize -value "10M"
            Set-PHPSetting -name fastcgi.impersonate -Value '0'
            Set-PHPSetting -name max_execution_time -Value '300'
            #Move logging and temp space to e:
            Set-PHPSetting -name upload_tmp_dir -value $php_temp
            set-phpsetting -name session.save_path -value $php_temp
            Set-PHPSetting -name error_log -value "$php_log\php-errors.log"
            Set-PHPExtension -name php_wincache.dll -status enabled

            if ((Test-Path -path $web_root) -ne $True) {
                new-item -type directory -path $web_root
                $acl = get-acl $web_root
                $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users", "ReadAndExecute", "ContainerInherit, ObjectInherit", "None","Allow")
                $acl.setaccessrule($ar)
                set-acl $web_root $acl
            }

            if ((Test-Path -path $web_log) -ne $True) {
                new-item -type directory -path $web_log
                $acl = get-acl $web_log
                $ar = new-object system.security.accesscontrol.filesystemaccessrule("Users", "ReadAndExecute", "ContainerInherit, ObjectInherit", "None","Allow")
                $acl.setaccessrule($ar)
                set-acl $web_log $acl
            }

        }
		GetScript = { # should return a hashtable representing the state of the current node
            $result = $true
            if ( (Get-PSSnapin -Name PHPManagerSnapin -ErrorAction SilentlyContinue) -eq $null )
            {
                $result = $false 
            }
			@{
				"PHPConfigured" = $result
			}
		}
        DependsOn = "[Script]PHPACLs"
    }
	# Configure IIS
	Script ConfigureIIS
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            $result = Test-Path -path "$env:SystemDrive\inetpub\wwwroot\request"

            return $result
        }
        SetScript = {
            $HostHeader = "$VM_Name_Suffix.ejukebox.net"
            $CertSubject = 'ejukebox.net'
            $Username = 'ejukebox.scrps.acces'
            $Password = $eJukeboxScriptsAccess_credential

            #$cred = Get-Credential

            Import-Module WebAdministration
            $thumbprint = Get-ChildItem -Path Cert:\LocalMachine\My |
            where {$_.Subject -match $CertSubject -and $_.HasPrivateKey -eq 'True'} | Select-Object -ExpandProperty Thumbprint
            #Add HTTPS port 443 binding
            New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https -HostHeader $hostheader
            Get-Item -Path "cert:\localmachine\my\$thumbprint" | New-Item -path IIS:\SslBindings\0.0.0.0!443!$hostheader
            #Remove-Item -path IIS:\SslBindings\0.0.0.0!443
            #Get-Item IIS:\SslBindings\0.0.0.0!443 | Remove-Item
            #Set Physical Path for Default Website
            if ((Test-Path -path "$env:SystemDrive\inetpub\wwwroot\request") -ne $True) {
                new-item -type directory -path "$env:SystemDrive\inetpub\wwwroot\request"
            }
            Set-ItemProperty 'IIS:\sites\Default Web Site' -Name physicalpath -Value $env:SystemDrive\inetpub\wwwroot\request
            #Create scripts IIS application
            New-Item -ItemType Directory -Path C:\inetpub\wwwroot\request\scripts
            New-Item 'IIS:\sites\Default Web Site\scripts' -physicalPath C:\inetpub\wwwroot\request\scripts -Type Application

            #Set Require SSL to the scripts application
            Set-webconfigurationproperty -Filter //security/access -Name sslflags -Value "Ssl" –PSPath IIS:\  -location 'Default Web Site/scripts'
            #Install Basic Authentication
            dism /online /enable-feature /featurename:IIS-BasicAuthentication


            #Disable anonymous authentication
            $process = 'cmd.exe'
            $arguments = '/c  %systemroot%\System32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/authentication/anonymousAuthentication'
            start-process $process -ArgumentList $arguments -Wait

            $process = 'cmd.exe'
            $arguments = '/c  %systemroot%\System32\inetsrv\appcmd.exe set config "Default Web Site/scripts" -section:system.webServer/security/authentication/anonymousAuthentication -enabled:false -commitpath:"Default Web Site/scripts"'
            start-process $process -ArgumentList $arguments -Wait

            #Enable basic authentication only on the Scripts application
            $process = 'cmd.exe'
            $arguments = '/c  %systemroot%\System32\inetsrv\appcmd.exe unlock config -section:system.webServer/security/authentication/basicAuthentication'
            start-process $process -ArgumentList $arguments -Wait

            $process = 'cmd.exe'
            $arguments = '/c  %systemroot%\System32\inetsrv\appcmd.exe set config "Default Web Site/scripts" -section:system.webServer/security/authentication/basicAuthentication -enabled:true -commitpath:"Default Web Site/scripts"'
            start-process $process -ArgumentList $arguments -Wait

        }
		GetScript = { # should return a hashtable representing the state of the current node
            $result = Test-Path -path "$env:SystemDrive\inetpub\wwwroot\request"
			@{
				"IISConfigured" = $result
			}
		}
        DependsOn = @("[Script]PHPACLs","[User]ejukeboxScrpsAcces")
    }
	# Configure IIS Application Pool
	Script ConfigureIISApplicationPool
	{
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            Import-Module WebAdministration
            if ((Get-ItemProperty 'IIS:\sites\Default Web Site\scripts' -Name applicationPool).value -notmatch 'Default') {return $True}
			else {return $False}
            
        }
        SetScript = {
            #Add scripts application to new application pool
            Import-Module WebAdministration
            Set-ItemProperty 'IIS:\sites\Default Web Site\scripts' -Name applicationPool -Value eJukeScripts

        }
		GetScript = { # should return a hashtable representing the state of the current node
            Import-Module WebAdministration
            $result = (Get-ItemProperty 'IIS:\sites\Default Web Site\scripts' -Name applicationPool).value
			@{
				"Application Pool" = $result
			}
		}
        DependsOn = "[xWebAppPool]eJukeScripts"
    }

#endregion


################################################################################
##################     xWebAdministration
################################################################################
#region Users & Groups
	# Configure PHP for IIS
	xWebAppPool eJukeScripts
	{
        Name = "eJukeScripts"
        Ensure = "Present"
        enable32BitAppOnWin64 = $true
        autoStart = $true
        LoadUserProfile = $false
        startMode = "AlwaysRunning"
        identityType = 'SpecificUser'
        DependsOn = "[Script]ConfigureIIS"
        Credential = $eJukeboxAppPool_credential
    }
#endregion

################################################################################
##################     Users & Groups
################################################################################
#region Users & Groups
	User eJukeboxTask
	{
        UserName = $eJukeboxTask_credential.UserName
        Description = 'eJukebox account to run scheduled tasks'
        Disabled = $false
        Ensure = 'Present'
        FullName = 'eJukebox Task'
        Password = $eJukeboxTask_credential
        PasswordChangeNotAllowed = $false
        PasswordChangeRequired = $False
        PasswordNeverExpires = $true
	}
	User eJukebox
	{
        UserName = $eJukebox_credential.UserName
        Description = 'Normal logon user account for eJukebox'
        Disabled = $false
        Ensure = 'Present'
        FullName = 'Marc Kean'
        Password = $eJukebox_credential
        PasswordChangeNotAllowed = $false
        PasswordChangeRequired = $False
        PasswordNeverExpires = $true
	}
	User ejukeboxAppPool
	{
        UserName = $eJukeboxAppPool_credential.UserName
        Description = 'eJukebox account to attached to an IIS app pool'
        Disabled = $false
        Ensure = 'Present'
        FullName = 'eJukebox App Pool'
        Password = $eJukeboxAppPool_credential
        PasswordChangeNotAllowed = $false
        PasswordChangeRequired = $False
        PasswordNeverExpires = $true
	} 
	User ejukeboxScrpsAcces
	{
        UserName = $ejukeboxScrpsAcces_credential.UserName
        Description = 'eJukebox account used with the app to access the script site'
        Disabled = $false
        Ensure = 'Present'
        FullName = 'eJukebox Scripts Access'
        Password = $ejukeboxScrpsAcces_credential
        PasswordChangeNotAllowed = $false
        PasswordChangeRequired = $False
        PasswordNeverExpires = $true
	}
	Group Administrators
	{
        GroupName = 'Administrators'
        MembersToInclude = @('eJukebox.Task','marc.kean')
        DependsOn = '[User]eJukeboxTask'
	}
	#endregion

################################################################################
##################     Registry Stuff
################################################################################
#region Registry Stuff
	Registry ExecutionPolicy 
	{
        Ensure = 'Present'
        Key = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\'
        ValueName = 'ExecutionPolicy'
        ValueData = 'Unrestricted'
        ValueType = "String"
    }
	# Auto Logon
	Registry AutoAdminLogon 
	{
        Ensure = 'Present'
        Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName = 'AutoAdminLogon'
        ValueData = '1'
        ValueType = "String"
    }
	Registry DefaultUserName 
	{
        Ensure = 'Present'
        Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName = 'DefaultUserName'
        ValueData = 'marc.kean'
        ValueType = "String"
    }
	Registry DefaultPassword 
	{
        Ensure = 'Present'
        Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName = 'DefaultPassword'
        ValueData = 'q@pm0c105300'
        ValueType = "String"
    }
	# Disable IE First Launch
	Registry DisableFirstRunCustomize 
	{
        Ensure = 'Present'
        Key = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Main'
        ValueName = 'DisableFirstRunCustomize'
        ValueData = '1'
        ValueType = "String"
    }
	#endregion

################################################################################
##################     Windows Services
################################################################################
#region Windows Services
	Service IIS 
	{
        Name = 'W3SVC'
        State = 'Running'
        DependsOn = '[xWebAppPool]eJukeScripts'
    }
	<#Service SHOUTCast 
	{
        Name = 'Shoutcast'
        State = 'Running'
        Credential = $eJukebox_credential
        DependsOn = '[Script]SHOUTcastService'
    }#>

	#endregion

  }

}
