param (
    [string]$artifactsLocation,
    [string]$artifactsLocationSasToken,
    [string]$folderName,
    [string]$fileToInstall
)

$source = $artifactsLocation + "$folderName\$fileToInstall" + $artifactsLocationSasToken
$dest = "C:"
#New-Item -Path $dest -ItemType directory
Invoke-WebRequest $source -OutFile "$dest\$fileToInstall"

<# Dropbox
$dropboxDBfile = Get-ChildItem -Path $env:USERPROFILE\AppData\Local -Recurse -ErrorAction SilentlyContinue | ? {$_.Name -eq 'host.db'}
$base64path = gc $dropboxDBfile.FullName | select -index 1
# -index 1 is the 2nd line in the file
$dropboxPath = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($base64path)) # convert from base64 to ascii

# Custom Script for Windows 
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId (Get-CimInstance �ClassName Win32_ComputerSystem | Select-Object -expand UserName)
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal
Register-ScheduledTask Notepad -InputObject $task
#>

<#
# This will create a schduled task which will run a UserLogonScript for any user that logs on changing the regional settings for the user to Australia.
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

#>

# Change System Locale to English (Australia)
Set-WinSystemLocale -SystemLocale en-AU

# Restart the computer after changing the system locale
#Restart-Computer -Force