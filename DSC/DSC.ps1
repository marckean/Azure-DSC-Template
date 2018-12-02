#region Node Configuration (Main)
configuration Main
{
param
(
[string]$VM_Name_Suffix = "localhost",
[string]$nodeName = $env:COMPUTERNAME,
[string]$VNCKey
)

#Import-DscResource -Name 'xRemoteFile' -ModuleName '.\xPSDesiredStateConfiguration'
<# xPSDesiredStateConfiguration containes....
xDscWebService, xWindowsProcess, xService, xPackage
xArchive, xRemoteFile, xPSEndpoint, xWindowsOptionalFeature
#>

$BuildData = "$env:SystemDrive\SourceFiles"
Node $env:COMPUTERNAME
  {
    File BuildData
    {
        DestinationPath = $BuildData
        Ensure = 'Present'
        Type = 'Directory'
    }

################################################################################
##################     Packages
################################################################################
#region Packages
    Package InstallVNCServer
    {
        Ensure = "Present"
        Path = "$BuildData\VNC-Server-5.3.2-Windows-en-64bit.msi"
        Name = "VNC Server 5.3.2"
        ProductId = "{BD3BF59A-3CD6-49B3-A166-E57BF55FF959}"
        #DependsOn = "[Script]UnEncryptScripts"
        #Arguments = "ADDLOCAL=ALL"
        DependsOn = "[Script]RealVNCCopy"
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
    Script RealVNCCopy
    {
        TestScript = { # the TestScript block runs first. If the TestScript block returns $false, the SetScript block will run
            Test-Path "$using:BuildData\VNC-Server-5.3.2-Windows-en-64bit.msi"
        }
        SetScript = {
            $source = $using:artifacts + "RealVNC/VNC-Server-5.3.2-Windows-en-64bit.msi" + $using:artifactsSasToken
            $dest = "$using:BuildData\VNC-Server-5.3.2-Windows-en-64bit.msi"
            Invoke-WebRequest $source -OutFile $dest
        }
		GetScript = { # should return a hashtable representing the state of the current node
            $result = Test-Path "$using:BuildData\VNC-Server-5.3.2-Windows-en-64bit.msi"
			@{
				"Downloaded" = $result
			}
		}
    DependsOn = "[File]BuildData"
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

  }

}