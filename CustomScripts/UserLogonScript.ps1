#
# UserLogonScript.ps1
#
# New-PSDrive -Name HKU -PSProvider Registry -Root "HKEY_USERS"

Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'sShortDate' -Value "d/M/yyyy"
Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'sLongDate' -Value "dddd,d MMMM,yyyy"
Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'sShortTime' -Value "h:mm tt"
Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'sTimeFormat' -Value "h:mm:ss tt"
Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'iFirstDayOfWeek' -Value "6"
Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'sCountry' -Value "Australia"
Set-ItemProperty -Path 'HKCU:\Control Panel\International' -Name 'LocaleName' -Value "en-AU"
Set-ItemProperty -Path 'HKCU:\Control Panel\International\Geo' -Name 'Nation' -Value "12"