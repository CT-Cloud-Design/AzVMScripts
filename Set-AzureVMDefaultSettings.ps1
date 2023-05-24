<#
.SYNOPSIS
A script used to set customized server settings on Azure Windows VMs running Windows Server 2016, Windows Server 2019 or Windows Server 2022.
.DESCRIPTION
A script used to set customized server settings on Azure Windows VMs running Windows Server 2016, Windows Server 2019 or Windows Server 2022.
This script will do all of the following:
Check if the PowerShell window is running as Administrator (which is a requirement), otherwise the PowerShell script will be exited.
Allow ICMP (ping) through Windows Firewall for IPv4 and IPv6.
Enable Remote Desktop (RDP) and enable Windows Firewall rule.
Enable secure RDP authentication Network Level Authentication (NLA).
Enable Remote Management (for RSAT tools and Windows Admin Center) and enable Windows Firewall rules.
Enable User Account Control (UAC).
Disable RDP printer mapping.
Disable IE security for Administrators.
Disable Windows Admin Center pop-up.
Disable Server Manager at logon.
Disable guest account.
Disable Hibernation.
Set Windows Diagnostic level (Telemetry) to Security (no Windows diagnostic data will be sent).
Set Folder Options.
Set volume label of C: to OS.
Set Time Zone (UTC+01:00).
Set Power Management to High Performance, if it is not currently the active plan.
Set the Interactive Login to "Do not display the last username".
Set language to En-US and keyboard to German.
Create the C:\Temp folder, if it does not exist.
Remove description of the Local Administrator Account.
Automount disable
Ipv4 before ipv6
Set controlled folder access to audit mode
Enable 'Local Security Authority (LSA) protection
Disable 'Enumerate administrator accounts on elevation'"
Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile
Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile
Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile
Enable 'Apply UAC restrictions to local accounts on network logons
Disable 'Installation and configuration of Network Bridge on your DNS domain network
Needed for Application Guard
Enable 'Require domain users to elevate when setting a network's location
Prohibit use of Internet Connection Sharing on your DNS domain network
Disable 'Always install with elevated privileges
Disable 'Autoplay for non-volume devices
Disable 'Autoplay' for all drives
Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands
Disable 'Allow Basic authentication' for WinRM Client
Disable 'Allow Basic authentication' for WinRM Service
Disable running or installing downloaded software with invalid signature
Set IPv6 source routing to highest protection
Disable IP source routing
Block outdated ActiveX controls for Internet Explorer
Disable Solicited Remote Assistance
Disable Anonymous enumeration of shares
Set 'Remote Desktop security level' to 'TLS'
Set user authentication for remote connections by using Network Level Authentication to 'Enabled'
Create new local Admin without sid500
Automatic Download ADConnect (Switch)
Install Domain-Controller Tools on Domain Controller (Switch)

Restart the server to apply all changes, five seconds after running the last command.

#Add later:
    Add Admin and Password from an to KeyVault

.NOTES
Disclaimer:     This script is provided "As Is" with no warranties.
.EXAMPLE
.\Set-AzureVMDefaultSettings.ps1
.\Set-AzureVMDefaultSettings.ps1 -AdminUsername "azadmin" -AdminPassword "password"
.\Set-AzureVMDefaultSettings.ps1 -ADDomainServices
.\Set-AzureVMDefaultSettings.ps1 -ADConnect
.LINK
#>

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Parameters
Param(
    [string]$AdminUsername,
    [string]$AdminPassword,
    [switch]$ADDomainServices,
    [switch]$ADConnect
)

## Variables

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$allowIcmpV4FirewallRuleName = "Allow_Ping_ICMPv4" # ICMPv4 Firewall Rule Name
$allowIcmpV4FirewallRuleDisplayName = "Allow Ping ICMPv4" # ICMPv4 Firewall Rule Display Name
$allowIcmpV4FirewallRuleDescription = "Packet Internet Groper ICMPv4"
$allowIcmpV6FirewallRuleName = "Allow_Ping_ICMPv6" # ICMPv6 Firewall Rule Name
$allowIcmpV6FirewallRuleDisplayName = "Allow Ping ICMPv6" # ICMPv6 Firewall Rule Display Name
$allowIcmpV6FirewallRuleDescription = "Packet Internet Groper ICMPv6"
$allowRdpDisplayName = "Remote Desktop*"
$wmiFirewallRuleDisplayGroup = "Windows Management Instrumentation (WMI)"
$remoteEventLogFirewallRuleDisplayGroup = "Remote Event Log Management"
$scheduledTaskNameServerManager = "ServerManager"
$windowsExplorerProcessName = "explorer"
$cDriveLabel = "OS" # Volume label of C:
$timezone = "W. Europe Standard Time" # Time zone
$powerManagement = "High performance"
$currentLangAndKeyboard = (Get-WinUserLanguageList).InputMethodTips
$keyboardInputMethod = "0407:00000407" # German
$tempFolder = "C:\Temp" # Temp folder name
$installFolder = "C:\Install" # Install folder name
$scriptsFolder = "C:\Scripts" # Install folder name
$administratorName = $env:UserName

$writeEmptyLine = "`n"
$writeSeperatorSpaces = " - "
$global:currenttime = Set-PSBreakpoint -Variable currenttime -Mode Read -Action {$global:currenttime= Get-Date -UFormat "%A %m/%d/%Y %R"}
$foregroundColor1 = "Red"
$foregroundColor2 = "Yellow"

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Create the folders, if it does not exist.

if (!(test-path $tempFolder))
{
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    Write-Host ($writeEmptyLine + "# $tempFolder folder created" + $writeSeperatorSpaces + $currentTime)`
    -foregroundcolor $foregroundColor2 $writeEmptyLine
}
else {
    Write-Host ($writeEmptyLine + "# $tempFolder folder exists" + $writeSeperatorSpaces + $currentTime)`
    -foregroundcolor $foregroundColor2 $writeEmptyLine
}

## ------------

if (!(test-path $installFolder))
{
    New-Item -ItemType Directory -Path $installFolder -Force | Out-Null

    Write-Host ($writeEmptyLine + "# $installFolder folder created" + $writeSeperatorSpaces + $currentTime)`
    -foregroundcolor $foregroundColor2 $writeEmptyLine
}
else {
    Write-Host ($writeEmptyLine + "# $installFolder folder exists" + $writeSeperatorSpaces + $currentTime)`
    -foregroundcolor $foregroundColor2 $writeEmptyLine
}

## ------------

if (!(test-path $scriptsFolder))
{
    New-Item -ItemType Directory -Path $scriptsFolder -Force | Out-Null

    Write-Host ($writeEmptyLine + "# $scriptsFolder folder created" + $writeSeperatorSpaces + $currentTime)`
    -foregroundcolor $foregroundColor2 $writeEmptyLine
}
else {
    Write-Host ($writeEmptyLine + "# $scriptsFolder folder exists" + $writeSeperatorSpaces + $currentTime)`
    -foregroundcolor $foregroundColor2 $writeEmptyLine
}

Start-Transcript -OutputDirectory "C:\Temp\"

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Check if PowerShell runs as Administrator, otherwise exit the script

if ($isAdministrator -eq $false) {
        # Check if running as Administrator, otherwise exit the script
        Write-Host ($writeEmptyLine + "# Please run PowerShell as Administrator" + $writeSeperatorSpaces + $global:currenttime)`
        -foregroundcolor $foregroundColor1 $writeEmptyLine
        Start-Sleep -s 3
        exit
} else {
        # If running as Administrator, start script execution    
        Write-Host ($writeEmptyLine + "# Script started. Without any errors, it will need around 2 minutes to complete" + $writeSeperatorSpaces + $currentTime)`
        -foregroundcolor $foregroundColor1 $writeEmptyLine 
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Allow ICMP (ping) through Windows Firewall for IPv4 and IPv6

# Allow ICMP IPv4
try {
    Get-NetFirewallRule -Name $allowIcmpV4FirewallRuleName -ErrorAction Stop | Out-Null
} catch {
    New-NetFirewallRule -Name $allowIcmpV4FirewallRuleName -DisplayName $allowIcmpV4FirewallRuleDisplayName -Description $allowIcmpV4FirewallRuleDescription -Protocol ICMPv4 -IcmpType 8 `
    -Enabled True -Profile Any -Action Allow | Out-Null
}

# Allow ICMP IPv6
try {
    Get-NetFirewallRule -Name $allowIcmpV6FirewallRuleName -ErrorAction Stop | Out-Null
} catch {
    New-NetFirewallRule -Name $allowIcmpV6FirewallRuleName -DisplayName $allowIcmpV6FirewallRuleDisplayName -Description $allowIcmpV6FirewallRuleDescription -Protocol ICMPv6 -IcmpType 8 `
    -Enabled True -Profile Any -Action Allow | Out-Null
}

Write-Host ($writeEmptyLine + "# ICMP allowed trough Windows Firewall for IPv4 and IPv6" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enable Remote Desktop (RDP) and enable Windows Firewall rule

Import-Module NetSecurity
(Get-WmiObject Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices).SetAllowTsConnections(1,1) | Out-Null
(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) | Out-Null

# Enable firewall rule for RDP 
try {
    Get-NetFirewallRule -DisplayName $allowRdpDisplayName -Enabled true -ErrorAction Stop | Out-Null
} catch {
    Set-NetFirewallRule -DisplayName $allowRdpDisplayName -Enabled true -PassThru | Out-Null
}

Write-Host ($writeEmptyLine + "# Remote Desktop enabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine 

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enable secure RDP authentication Network Level Authentication (NLA)

$rdpRegKeyPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$rdpRegKeyName = "UserAuthentication"

Set-ItemProperty -Path $rdpRegKeyPath -name $rdpRegKeyName -Value 1 | Out-Null

Write-Host ($writeEmptyLine + "# Secure RDP authentication Network Level Authentication enabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enable Remote Management (for RSAT tools and Windows Admin Center) and enable Windows Firewall rules

# Enable WinRM
Enable-PSRemoting -Force | Out-Null

# Enable remote authentication acceptance
Enable-WSManCredSSP -Role server -Force | Out-Null

# Enable firewall rules for remote management
try {
    Get-NetFirewallRule -DisplayGroup $wmiFirewallRuleDisplayGroup -Enabled true -ErrorAction Stop | Out-Null
} catch {
    Set-NetFirewallRule -DisplayGroup $wmiFirewallRuleDisplayGroup -Enabled true -PassThru | Out-Null
}

try {
    Get-NetFirewallRule -DisplayGroup $remoteEventLogFirewallRuleDisplayGroup -Enabled true -ErrorAction Stop | Out-Null
} catch {
    Set-NetFirewallRule -DisplayGroup $remoteEventLogFirewallRuleDisplayGroup -Enabled true -PassThru | Out-Null
}

Write-Host ($writeEmptyLine + "# Remote Management enabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enable User Account Control (UAC)

$uacRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacRegKeyName = "EnableLUA"

Set-ItemProperty -Path $uacRegKeyPath -Name $uacRegKeyName -Value 1 -Type DWord | Out-Null

 Write-Host ($writeEmptyLine + "# User Access Control (UAC) enabled" + $writeSeperatorSpaces + $currentTime)`
 -foregroundcolor $foregroundColor2 $writeEmptyLine
 
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable RDP printer mapping

$rdpPrinterMappingRegKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$rdpPrinterMappingRegKeyName = "fDisableCpm"

Set-ItemProperty -Path $rdpPrinterMappingRegKeyPath -Name $rdpPrinterMappingRegKeyName -Value 1 | Out-Null

Write-Host ($writeEmptyLine + "# RDP printer mapping disabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable IE security for Administrators

$adminIESecurityRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$adminIESecurityRegKeyName = "IsInstalled"

Set-ItemProperty -Path $adminIESecurityRegKeyPath -Name $adminIESecurityRegKeyName -Value 0 | Out-Null

# Stop and start Windows explorer process
Stop-Process -Name $windowsExplorerProcessName | Out-Null

Write-Host ($writeEmptyLine + "# IE Enhanced Security Configuration for the Administrator disabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Windows Admin Center pop-up

$serverManagerRegKeyPath = "HKLM:\SOFTWARE\Microsoft\ServerManager"
$wacPopPupKeyName = "DoNotPopWACConsoleAtSMLaunch"

Set-ItemProperty -Path $serverManagerRegKeyPath -Name $wacPopPupKeyName -Value 1 | Out-Null

Write-Host ($writeEmptyLine + "# Windows Admin Center pop-up is disabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Server Manager at logon

Get-ScheduledTask -TaskName $scheduledTaskNameServerManager | Disable-ScheduledTask | Out-Null

Write-Host ($writeEmptyLine + "# Server Manager disabled at startup" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable guest account

net user guest /active:no | Out-Null

Write-Host ($writeEmptyLine + "# Guest account disabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Hibernation

powercfg.exe /h off

Write-Host ($writeEmptyLine + "# Hibernation disabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Windows Diagnostic level (Telemetry) to Security (no Windows diagnostic data will be sent)

$windowsDiagnosticLevelRegKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$windowsDiagnosticLevelRegKeyName = "AllowTelemetry"

New-ItemProperty -Path $windowsDiagnosticLevelRegKeyPath -Name $windowsDiagnosticLevelRegKeyName -PropertyType "DWord" -Value 0 -Force | Out-Null

Write-Host ($writeEmptyLine + "# Windows Diagnostic level (Telemetry) set to Security" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set the Interactive Login to "Do not display the last username"

$interActiveLogonRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$interActiveLogonRegKeyName = "DontDisplayLastUsername"

Set-ItemProperty -Path $interActiveLogonRegKeyPath -Name $interActiveLogonRegKeyName -Value 1 | Out-Null

Write-Host ($writeEmptyLine + "# Interactive Login set to - Do not display last user name" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Folder Options

$folderOptionsRegKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" # Per-User
$folderOptionsHiddenRegKeyName = "Hidden"
$folderOptionsHideFileExtRegKeyName = "HideFileExt" 
$folderOptionsShowSuperHiddenRegKeyName = "ShowSuperHidden" 
$folderOptionsHideDrivesWithNoMediaRegKeyName = "HideDrivesWithNoMedia" 
$folderOptionsSeperateProcessRegKeyName = "SeperateProcess" 
$folderOptionsAlwaysShowMenusRegKeyName = "AlwaysShowMenus" 

Set-ItemProperty -Path $folderOptionsRegKeyPath -Name  $folderOptionsHiddenRegKeyName -Value 1 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name  $folderOptionsHideFileExtRegKeyName -Value 0 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsShowSuperHiddenRegKeyName -Value 0 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsHideDrivesWithNoMediaRegKeyName -Value 0 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsSeperateProcessRegKeyName -Value 1 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsAlwaysShowMenusRegKeyName -Value 1 | Out-Null

# Stop and start Windows explorer process
Stop-Process -processname $windowsExplorerProcessName -Force | Out-Null

Write-Host ($writeEmptyLine + "# Folder Options set" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set volume label of C: to OS

$drive = Get-WmiObject win32_volume -Filter "DriveLetter = 'C:'"
$drive.Label = $cDriveLabel
$drive.put() | Out-Null

Write-Host ($writeEmptyLine + "# Volumelabel of C: set to $cDriveLabel" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Time Zone (UTC+01:00)

Set-TimeZone -Name $timezone

Write-Host ($writeEmptyLine + "# Timezone set to $timezone" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Power Management to High Performance, if it is not currently the active plan

try {
    $highPerf = powercfg -l | ForEach-Object {if($_.contains($powerManagement)) {$_.split()[3]}}
    $currPlan = $(powercfg -getactivescheme).split()[3]
    if ($currPlan -ne $highPerf) {powercfg -setactive $highPerf}
    Write-Host ($writeEmptyLine + "# Power Management set to $powerManagement" + $writeSeperatorSpaces + $currentTime)`
    -foregroundcolor $foregroundColor2 $writeEmptyLine
} catch {
    Write-Warning -Message ($writeEmptyLine + "# Unable to set power plan to $powerManagement" + $writeSeperatorSpaces + $currentTime)`
    -foregroundcolor $foregroundColor1 $writeEmptyLine
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set language to En-US and keyboard to German

if ($currentLangAndKeyboard -eq "0409:00000409") {
        $langList = New-WinUserLanguageList en-US
        $langList[0].InputMethodTips.Clear()
        $langList[0].InputMethodTips.Add($keyboardInputMethod) 
        Set-WinUserLanguageList $langList -Force
        Write-Host ($writeEmptyLine + "# Keybord set to German" + $writeSeperatorSpaces + $currentTime)`
        -foregroundcolor $foregroundColor2 $writeEmptyLine
} else {
	    Write-Host ($writeEmptyLine + "# Keybord all ready set to German" + $writeSeperatorSpaces + $currentTime)`
        -foregroundcolor $foregroundColor2 $writeEmptyLine
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Remove description of the Local Administrator Account

Set-LocalUser -Name $administratorName -Description ""

Write-Host ($writeEmptyLine + "# Description removed from Local Administrator Account" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Automount

$automountRegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mountmgr"
$automountRegKeyName = "NoAutoMount"

Set-ItemProperty -Path $automountRegKeyPath -name $automountRegKeyName -Value 1 | Out-Null

Write-Host ($writeEmptyLine + "# Automount Disabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## IPv4 before IPv6

$ipv4v6RegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$ipv4v6RegKeyName = "DisabledComponents "

New-ItemProperty -Path $ipv4v6RegKeyPath -name $ipv4v6RegKeyName -PropertyType DWORD -Value "0x20" | Out-Null

Write-Host ($writeEmptyLine + "# IPv4 before IPv6 changed" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Hardening

Write-Host ($writeEmptyLine + "Set controlled folder access to audit mode" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v EnableControlledFolderAccess /t REG_DWORD /d "2" /f

## --------

Write-Host ($writeEmptyLine + "Enable 'Local Security Authority (LSA) protection'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

## --------

Write-Host ($writeEmptyLine + "Disable 'Enumerate administrator accounts on elevation'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v EnumerateAdministrators /t REG_DWORD /d 0 /f

## --------

Write-Host ($writeEmptyLine + "Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DisableNotifications /t REG_DWORD /d 1 /f

## --------

Write-Host ($writeEmptyLine + "Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfiles" /v DisableNotifications /t REG_DWORD /d 1 /f

## --------

Write-Host ($writeEmptyLine + "Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DisableNotifications /t REG_DWORD /d 1 /f

## --------

Write-Host ($writeEmptyLine + "Enable 'Apply UAC restrictions to local accounts on network logons'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f

## --------

Write-Host ($writeEmptyLine + "Disable 'Installation and configuration of Network Bridge on your DNS domain network'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
## --------

Write-Host ($writeEmptyLine + "Wird für Application Guard benötigt" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_AllowNetBridge_NLA /t REG_DWORD /d 0 /f

## --------

Write-Host ($writeEmptyLine + "Enable 'Require domain users to elevate when setting a network's location'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_StdDomainUserSetLocation /t REG_DWORD /d 1 /f

## --------

Write-Host ($writeEmptyLine + "Prohibit use of Internet Connection Sharing on your DNS domain network" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f

## --------

Write-Host ($writeEmptyLine + "Disable 'Always install with elevated privileges'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f

## --------

Write-Host ($writeEmptyLine + "Disable 'Autoplay for non-volume devices'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f

## --------

Write-Host ($writeEmptyLine + "Disable 'Autoplay' for all drives" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

## --------

Write-Host ($writeEmptyLine + "Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v NoAutorun /t REG_DWORD /d 1 /f

## --------

Write-Host ($writeEmptyLine + "Disable 'Allow Basic authentication' for WinRM Client" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowBasic /t REG_DWORD /d 0 /f

## --------

Write-Host ($writeEmptyLine + "Disable 'Allow Basic authentication' for WinRM Service" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" /v AllowBasic /t REG_DWORD /d 0 /f

## --------

Write-Host ($writeEmptyLine + "Disable running or installing downloaded software with invalid signature" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 0 /f

## --------

#Write-Host ($writeEmptyLine + "Set IPv6 source routing to highest protection" + $writeSeperatorSpaces + $currentTime)`
#-foregroundcolor $foregroundColor2 $writeEmptyLine
#reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

## --------

Write-Host ($writeEmptyLine + "Disable IP source routing" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

## --------

Write-Host ($writeEmptyLine + "Block outdated ActiveX controls for Internet Explorer" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext" /v VersionCheckEnabled /t REG_DWORD /d 1 /f

## --------

Write-Host ($writeEmptyLine + "Disable Solicited Remote Assistance" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

## --------

Write-Host ($writeEmptyLine + "Disable Anonymous enumeration of shares" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f

## --------

Write-Host ($writeEmptyLine + "Set 'Remote Desktop security level' to 'TLS'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f

## --------

Write-Host ($writeEmptyLine + "Set user authentication for remote connections by using Network Level Authentication to 'Enabled'" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f

### !Attention only use when necessary 
    ### --------

Write-Host "Enable 'Microsoft network client: Digitally sign communications (always)'"
#    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

    #Write-Host "Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'"
#    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f

    #Bei VMs ohne Domäne kein RDP Zugang mehr möglich
    #Write-Host "Disable merging of local Microsoft Defender Firewall rules with group policy firewall rules for the Public profile"
#    reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v AllowLocalPolicyMerge /t REG_DWORD /d 0 /f

    #Bei VMs ohne Domäne kein RDP Zugang mehr möglich
    #Write-Host "Disable merging of local Microsoft Defender Firewall connection rules with group policy firewall rules for the Public profile"
#    reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v AllowLocalIPsecPolicyMerge /t REG_DWORD /d 0 /f

    #Write-Host "Set User Account Control (UAC) to automatically deny elevation requests"
#    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f

    # Schedule Task gehen nicht mehr (außer System)
    #Write-Host "Disable the local storage of passwords and credentials"
#    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /t REG_DWORD /d 1 /f''

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## ASR-Rules

Write-Host ($writeEmptyLine + "ASR Rules AuditMode" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
#Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions AuditMode

Write-Host ($writeEmptyLine + "ASR Rules enabled" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor2 $writeEmptyLine
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

Get-MpPreference 

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Create new local Admin without sid500

function Add-LocalAdmin {
    [CmdletBinding()]
    param (
        [string] $NewLocalAdmin,
        [securestring] $Password
    )    
    begin {
    }    
    process {
        New-LocalUser "$NewLocalAdmin" -Password $Password -FullName "$NewLocalAdmin" -Description ""
        Write-Verbose "$NewLocalAdmin local user crated"
        Add-LocalGroupMember -Group "Administrators" -Member "$NewLocalAdmin"
        Write-Verbose "$NewLocalAdmin added to the local administrator group"
    }    
    end {
    }
}

if ($AdminUsername) {

    Write-Host ($writeEmptyLine + "Creating local admin -> user set to:" + $AdminUsername + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## Add to KeyVault
    if ($AdminPassword) {
    [Security.SecureString]$securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    Write-Host ($writeEmptyLine + "Creating local admin -> password is set" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
        Add-LocalAdmin -NewLocalAdmin $AdminUsername -Password $securePassword -Verbose
    }
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Download AD-Connect

if ($ADConnect) {

    $ADConnectUrl = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=47594"

    Write-Host ($writeEmptyLine + "Download AD-Connect" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

    $source=Invoke-WebRequest $ADConnectUrl -UseBasicParsing -MaximumRedirection 0 
    $source.Links | Where-Object {$_.innerText -contains "download"} |Select-Object -expand href -OutVariable $sourceadw
    $webrequest = $source.Links | Where-Object {$_.href -like "*.msi"} | Select-Object -expand href
    $outpath = "C:\Install\" + $(split-path -path "$webrequest" -leaf)
    Invoke-WebRequest $webrequest[0] -UseBasicParsing -OutFile $outpath

}
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Install Windows Features for Domain Controllers

if ($ADDomainServices) {
    
    Write-Host ($writeEmptyLine + "Install AD-Domain-Services" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Extend Partition OS Drive

$driveLetter = "C"

$MaxSize = (Get-PartitionSupportedSize -DriveLetter $driveLetter).sizeMax
if ((get-partition -driveletter C).size -eq $MaxSize) {
    Write-Output "The drive $driveLetter is already at its maximum drive size"
}else {
    Resize-Partition -DriveLetter $driveLetter -Size $MaxSize
    Write-Output "The drive $driveLetter was already at its maximum drive size, nothing changed"
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Restart server to apply all changes, five seconds after running the last command

Write-Host ($writeEmptyLine + "# This server will restart to apply all changes" + $writeSeperatorSpaces + $currentTime)`
-foregroundcolor $foregroundColor1 $writeEmptyLine

Stop-Transcript

Start-Sleep -s 5
Restart-Computer -ComputerName localhost

