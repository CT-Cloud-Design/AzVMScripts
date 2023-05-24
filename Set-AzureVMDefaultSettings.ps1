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
BCEDIT
Firewall Policys with port 3389 (RDP)

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
$allowIcmpV4FirewallRuleName = "Allow_Ping1_ICMPv4" # ICMPv4 Firewall Rule Name
$allowIcmpV4FirewallRuleDisplayName = "Allow Ping1 ICMPv4" # ICMPv4 Firewall Rule Display Name
$allowIcmpV4FirewallRuleDescription = "Packet Internet1 ICMPv4"
$allowIcmpV6FirewallRuleName = "Allow_Ping1_ICMPv6" # ICMPv6 Firewall Rule Name
$allowIcmpV6FirewallRuleDisplayName = "Allow Ping1 ICMPv6" # ICMPv6 Firewall Rule Display Name
$allowIcmpV6FirewallRuleDescription = "Packet Internet1 ICMPv6"
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

$writeEmptyLine = "`n"
$writeSeperatorSpaces = " - "
$global:currenttime = Set-PSBreakpoint -Variable currenttime -Mode Read -Action {$global:currenttime= Get-Date -UFormat "%A %m/%d/%Y %R"}
$foregroundColor1 = "Red"
$foregroundColor2 = "Yellow"

Set-Content -Encoding UTF8 -Path "c:\temp\test.txt" -Value "" 

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

function Add-Result {
    [CmdletBinding()]
    param (
        [string] $description,
        [switch] $changed,
        [switch] $ok,
        [switch] $failed
    )    
    begin {
    }    
    process {
        $newText = "["
        if ($changed) { $newText += "X|" } else { $newText += " |"} 
        if ($ok) { $newText += "X|" } else { $newText += " |"} 
        if ($failed) { $newText += "X]" } else { $newText += " ]"}
        $newText += " " + $description  
        Add-Content -Encoding UTF8 -Path "c:\temp\test.txt" -Value $newText 
    }    
    end {
    }
}

## Create the folders, if it does not exist.

if (!(test-path $tempFolder))
{
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
    Write-Host ($writeEmptyLine + "# $tempFolder folder created" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    Add-Result -description "# $tempFolder folder created" -changed -ok
}
else {
    Write-Host ($writeEmptyLine + "# $tempFolder folder exists" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    Add-Result -description "# $tempFolder folder exists" -ok
}

## ------------

if (!(test-path $installFolder))
{
    New-Item -ItemType Directory -Path $installFolder -Force | Out-Null
    Write-Host ($writeEmptyLine + "# $installFolder folder created" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    Add-Result -description "# $installFolder folder created" -changed -ok
}
else {
    Write-Host ($writeEmptyLine + "# $installFolder folder exists" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    Add-Result -description "# $installFolder folder exists" -ok
}

## ------------

if (!(test-path $scriptsFolder))
{
    New-Item -ItemType Directory -Path $scriptsFolder -Force | Out-Null
    Write-Host ($writeEmptyLine + "# $scriptsFolder folder created" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    Add-Result -description "# $scriptsFolder folder created" -changed -ok
}
else {
    Write-Host ($writeEmptyLine + "# $scriptsFolder folder exists" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    Add-Result -description "# $scriptsFolder folder exists" -ok
}

Start-Transcript -OutputDirectory "C:\Temp\"

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Debug
$secCurrentContext = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host ($writeEmptyLine + "# ENV-Username: $env:USERNAME" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
Write-Host ($writeEmptyLine + "# secCurrentContext: $secCurrentContext" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
Write-Host ($writeEmptyLine + "# ENV-Computername: $env:COMPUTERNAME" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Check if PowerShell runs as Administrator, otherwise exit the script

if ($isAdministrator -eq $false) {
        # Check if running as Administrator, otherwise exit the script
        Write-Host ($writeEmptyLine + "# Please run PowerShell as Administrator" + $writeSeperatorSpaces + $global:currenttime) -foregroundcolor $foregroundColor2 $writeEmptyLine
        Start-Sleep -s 3
        exit
} else {
        # If running as Administrator, start script execution    
        Write-Host ($writeEmptyLine + "# Script started. Without any errors, it will need around 2 minutes to complete" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine 
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Allow ICMP (ping) through Windows Firewall for IPv4 and IPv6

# Allow ICMP IPv4
try {
    Get-NetFirewallRule -Name $allowIcmpV4FirewallRuleName -ErrorAction Stop | Out-Null
    Add-Result -description "# Allow ICMP (ping) through Windows Firewall for IPv4" -ok
} catch {
    New-NetFirewallRule -Name $allowIcmpV4FirewallRuleName -DisplayName $allowIcmpV4FirewallRuleDisplayName -Description $allowIcmpV4FirewallRuleDescription -Protocol ICMPv4 -IcmpType 8 `
    -Enabled True -Profile Any -Action Allow | Out-Null
    Add-Result -description "# Allow ICMP (ping) through Windows Firewall for IPv4" -ok -changed
}

# Allow ICMP IPv6
try {
    Get-NetFirewallRule -Name $allowIcmpV6FirewallRuleName -ErrorAction Stop | Out-Null
    Add-Result -description "# Allow ICMP (ping) through Windows Firewall for IPv6" -ok
} catch {
    New-NetFirewallRule -Name $allowIcmpV6FirewallRuleName -DisplayName $allowIcmpV6FirewallRuleDisplayName -Description $allowIcmpV6FirewallRuleDescription -Protocol ICMPv6 -IcmpType 8 `
    -Enabled True -Profile Any -Action Allow | Out-Null
    Add-Result -description "# Allow ICMP (ping) through Windows Firewall for IPv6" -ok -changed
}

Write-Host ($writeEmptyLine + "# ICMP allowed trough Windows Firewall for IPv4 and IPv6" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enable Remote Desktop (RDP) and enable Windows Firewall rule

$allowRdpDisplayName = "Remote Desktop*"

Import-Module NetSecurity
(Get-WmiObject Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices).SetAllowTsConnections(1,1) | Out-Null
(Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0) | Out-Null

# Enable firewall rule for RDP 
try {
    Get-NetFirewallRule -DisplayName $allowRdpDisplayName | ForEach-Object {
        Get-NetFirewallRule -Enabled True -ErrorAction Stop | Out-Null
    }
    Add-Result -description "# Remote Desktop is now enabled" -ok
    Write-Host ($writeEmptyLine + "# Remote Desktop was already enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
} catch {
    Set-NetFirewallRule -DisplayName $allowRdpDisplayName -Enabled true -PassThru | Out-Null
    Write-Host ($writeEmptyLine + "# Remote Desktop is now enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    Add-Result -description "# Remote Desktop is now enabled" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enable secure RDP authentication Network Level Authentication (NLA)

$rdpRegKeyPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$rdpRegKeyName = "UserAuthentication"

Set-ItemProperty -Path $rdpRegKeyPath -name $rdpRegKeyName -Value 1 | Out-Null
Add-Result -description "# Secure RDP authentication Network Level Authentication enabled" -ok -changed

Write-Host ($writeEmptyLine + "# Secure RDP authentication Network Level Authentication enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enable Remote Management (for RSAT tools and Windows Admin Center) and enable Windows Firewall rules

# Enable WinRM
Enable-PSRemoting -Force | Out-Null

# Enable remote authentication acceptance
Enable-WSManCredSSP -Role server -Force | Out-Null

# Enable firewall rules for remote management
try {
    Get-NetFirewallRule -DisplayGroup $wmiFirewallRuleDisplayGroup -Enabled true -ErrorAction Stop | Out-Null
    Add-Result -description "# Enable firewall rules for remote management (WMI)" -ok
} catch {
    Set-NetFirewallRule -DisplayGroup $wmiFirewallRuleDisplayGroup -Enabled true -PassThru | Out-Null
    Add-Result -description "# Enable firewall rules for remote management (WMI)" -ok -changed
}

try {
    Get-NetFirewallRule -DisplayGroup $remoteEventLogFirewallRuleDisplayGroup -Enabled true -ErrorAction Stop | Out-Null
    Add-Result -description "# Enable firewall rules for remote management (Eventlog)" -ok
} catch {
    Set-NetFirewallRule -DisplayGroup $remoteEventLogFirewallRuleDisplayGroup -Enabled true -PassThru | Out-Null
    Add-Result -description "# Enable firewall rules for remote management (Eventlog)" -ok -changed
}

Write-Host ($writeEmptyLine + "# Remote Management enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enable User Account Control (UAC)

$uacRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacRegKeyName = "EnableLUA"

Set-ItemProperty -Path $uacRegKeyPath -Name $uacRegKeyName -Value 1 -Type DWord | Out-Null
Add-Result -description "# User Access Control (UAC) enabled" -ok -changed

 Write-Host ($writeEmptyLine + "# User Access Control (UAC) enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
 
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable RDP printer mapping

$rdpPrinterMappingRegKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$rdpPrinterMappingRegKeyName = "fDisableCpm"

Set-ItemProperty -Path $rdpPrinterMappingRegKeyPath -Name $rdpPrinterMappingRegKeyName -Value 1 | Out-Null
Add-Result -description "# RDP printer mapping disabled" -ok -changed

Write-Host ($writeEmptyLine + "# RDP printer mapping disabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable IE security for Administrators

$adminIESecurityRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$adminIESecurityRegKeyName = "IsInstalled"

Set-ItemProperty -Path $adminIESecurityRegKeyPath -Name $adminIESecurityRegKeyName -Value 0 | Out-Null

Add-Result -description "# IE Enhanced Security Configuration for the Administrator disabled" -ok -changed

# Stop and start Windows explorer process
if ($env:USERNAME -ne "$env:COMPUTERNAME") {
    # Stop and start Windows explorer process
    Stop-Process -processname $windowsExplorerProcessName -Force | Out-Null
}

Write-Host ($writeEmptyLine + "# IE Enhanced Security Configuration for the Administrator disabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Windows Admin Center pop-up

$serverManagerRegKeyPath = "HKLM:\SOFTWARE\Microsoft\ServerManager"
$wacPopPupKeyName = "DoNotPopWACConsoleAtSMLaunch"

Set-ItemProperty -Path $serverManagerRegKeyPath -Name $wacPopPupKeyName -Value 1 | Out-Null
Add-Result -description "# Windows Admin Center pop-up is disabled" -ok -changed

Write-Host ($writeEmptyLine + "# Windows Admin Center pop-up is disabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Server Manager at logon

Get-ScheduledTask -TaskName $scheduledTaskNameServerManager | Disable-ScheduledTask | Out-Null

Add-Result -description "# Server Manager disabled at startup" -ok -changed

Write-Host ($writeEmptyLine + "# Server Manager disabled at startup" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable guest account

net user guest /active:no | Out-Null
Add-Result -description "# Guest account disabled" -ok -changed

Write-Host ($writeEmptyLine + "# Guest account disabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Hibernation

powercfg.exe /h off
Add-Result -description "# Hibernation disabled" -ok -changed

Write-Host ($writeEmptyLine + "# Hibernation disabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Windows Diagnostic level (Telemetry) to Security (no Windows diagnostic data will be sent)

$windowsDiagnosticLevelRegKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$windowsDiagnosticLevelRegKeyName = "AllowTelemetry"

New-ItemProperty -Path $windowsDiagnosticLevelRegKeyPath -Name $windowsDiagnosticLevelRegKeyName -PropertyType "DWord" -Value 0 -Force | Out-Null
Add-Result -description "# Windows Diagnostic level (Telemetry) set to Security" -ok -changed

Write-Host ($writeEmptyLine + "# Windows Diagnostic level (Telemetry) set to Security" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set the Interactive Login to "Do not display the last username"

$interActiveLogonRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$interActiveLogonRegKeyName = "DontDisplayLastUsername"

Set-ItemProperty -Path $interActiveLogonRegKeyPath -Name $interActiveLogonRegKeyName -Value 1 | Out-Null
Add-Result -description "# Interactive Login set to - Do not display last user name" -ok -changed

Write-Host ($writeEmptyLine + "# Interactive Login set to - Do not display last user name" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Folder Options

$folderOptionsRegKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" # Per Default User 

if ($env:USERNAME -eq "$env:COMPUTERNAME") {
    reg load HKLM\DefaultUser C:\Users\Default\NTUSER.DAT
    $folderOptionsRegKeyPath = "HKLM:\Defaultuser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
}

$folderOptionsHiddenRegKeyName = "Hidden"
$folderOptionsHideFileExtRegKeyName = "HideFileExt" 
$folderOptionsShowSuperHiddenRegKeyName = "ShowSuperHidden" 
$folderOptionsHideDrivesWithNoMediaRegKeyName = "HideDrivesWithNoMedia" 
$folderOptionsSeperateProcessRegKeyName = "SeperateProcess" 
$folderOptionsAlwaysShowMenusRegKeyName = "AlwaysShowMenus" 

if (!(test-path $folderOptionsRegKeyPath)) {
    New-Item -Path $folderOptionsRegKeyPath | Out-Null
}

Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsHiddenRegKeyName -Value 1 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsHideFileExtRegKeyName -Value 0 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsShowSuperHiddenRegKeyName -Value 0 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsHideDrivesWithNoMediaRegKeyName -Value 0 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsSeperateProcessRegKeyName -Value 1 | Out-Null
Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsAlwaysShowMenusRegKeyName -Value 1 | Out-Null

if ($env:USERNAME -eq "$env:COMPUTERNAME") {
    reg unload HKLM\DefaultUser
} else {
    # Stop and start Windows explorer process
    Stop-Process -processname $windowsExplorerProcessName -Force | Out-Null
}

Add-Result -description "# Folder Options set" -ok -changed

Write-Host ($writeEmptyLine + "# Folder Options set" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set volume label of C: to OS

$drive = Get-WmiObject win32_volume -Filter "DriveLetter = 'C:'"
$drive.Label = $cDriveLabel
$drive.put() | Out-Null

Add-Result -description "# Volumelabel of C: set to $cDriveLabel" -ok -changed

Write-Host ($writeEmptyLine + "# Volumelabel of C: set to $cDriveLabel" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Time Zone (UTC+01:00)

Set-TimeZone -Name $timezone

Add-Result -description "# Timezone set to $timezone" -ok -changed

Write-Host ($writeEmptyLine + "# Timezone set to $timezone" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Power Management to High Performance, if it is not currently the active plan

try {
    $highPerf = powercfg -l | ForEach-Object {if($_.contains($powerManagement)) {$_.split()[3]}}
    $currPlan = $(powercfg -getactivescheme).split()[3]
    if ($currPlan -ne $highPerf) {powercfg -setactive $highPerf}
    Add-Result -description "# Power Management set to $powerManagement" -ok -changed

    Write-Host ($writeEmptyLine + "# Power Management set to $powerManagement" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
} catch {
    Write-Warning -Message ($writeEmptyLine + "# Unable to set power plan to $powerManagement" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor1 $writeEmptyLine
    Add-Result -description "# Unable to set power plan to $powerManagement" -failed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set language to En-US and keyboard to German

if ($currentLangAndKeyboard -eq "0409:00000409") {
        $langList = New-WinUserLanguageList en-US
        $langList[0].InputMethodTips.Clear()
        $langList[0].InputMethodTips.Add($keyboardInputMethod) 
        Set-WinUserLanguageList $langList -Force
        Add-Result -description "# Keybord set to German" -ok -changed
        Write-Host ($writeEmptyLine + "# Keybord set to German" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
} else {
        Add-Result -description "# Keybord set to German" -ok
	    Write-Host ($writeEmptyLine + "# Keybord all ready set to German" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Remove description of the Local Administrator Account

#$administratorName = $env:UserName

Set-LocalUser -Name aztmpadmin -Description ""

Add-Result -description "# Description removed from Local Administrator Account" -ok -changed

Write-Host ($writeEmptyLine + "# Description removed from Local Administrator Account" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Automount

$automountRegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mountmgr"
$automountRegKeyName = "NoAutoMount"

Set-ItemProperty -Path $automountRegKeyPath -name $automountRegKeyName -Value 1 | Out-Null

Add-Result -description "# Automount Disabled" -ok -changed

Write-Host ($writeEmptyLine + "# Automount Disabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## IPv4 before IPv6

$ipv4v6RegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$ipv4v6RegKeyName = "DisabledComponents"

try {
    Get-ItemProperty -Path $ipv4v6RegKeyPath -name $ipv4v6RegKeyName  | Out-Null
    Add-Result -description "# IPv4 before IPv6 was allready enabled" -ok
    Write-Host ($writeEmptyLine + "# IPv4 before IPv6 was allready enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
} catch {
    New-ItemProperty -Path $ipv4v6RegKeyPath -name $ipv4v6RegKeyName -PropertyType DWORD -Value "0x20" | Out-Null
    Add-Result -description "# IPv4 before IPv6 is now enabled" -ok -changed
    Write-Host ($writeEmptyLine + "# IPv4 before IPv6 is now enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Hardening

Write-Host ($writeEmptyLine + "Set controlled folder access to audit mode" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v EnableControlledFolderAccess /t REG_DWORD /d "2" /f
Add-Result -description "Set controlled folder access to audit mode" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Enable 'Local Security Authority (LSA) protection'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
Add-Result -description "Enable 'Local Security Authority (LSA) protection" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable 'Enumerate administrator accounts on elevation'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v EnumerateAdministrators /t REG_DWORD /d 0 /f
Add-Result -description "Disable 'Enumerate administrator accounts on elevation" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DisableNotifications /t REG_DWORD /d 1 /f
Add-Result -description "Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfiles" /v DisableNotifications /t REG_DWORD /d 1 /f
Add-Result -description "Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DisableNotifications /t REG_DWORD /d 1 /f
Add-Result -description "Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Enable 'Apply UAC restrictions to local accounts on network logons'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
Add-Result -description "Enable 'Apply UAC restrictions to local accounts on network logons" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable 'Installation and configuration of Network Bridge on your DNS domain network'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
## --------

Write-Host ($writeEmptyLine + "Needed by Application Guard" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_AllowNetBridge_NLA /t REG_DWORD /d 0 /f
Add-Result -description "Disable 'Installation and configuration of Network Bridge on your DNS domain network" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Enable 'Require domain users to elevate when setting a network's location'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_StdDomainUserSetLocation /t REG_DWORD /d 1 /f
Add-Result -description "Enable 'Require domain users to elevate when setting a network's location" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Prohibit use of Internet Connection Sharing on your DNS domain network" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f
Add-Result -description "Prohibit use of Internet Connection Sharing on your DNS domain network" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable 'Always install with elevated privileges'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
Add-Result -description "Disable 'Always install with elevated privileges" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable 'Autoplay for non-volume devices'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
Add-Result -description "Disable 'Autoplay for non-volume devices" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable 'Autoplay' for all drives" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
Add-Result -description "Disable 'Autoplay' for all drives" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v NoAutorun /t REG_DWORD /d 1 /f
Add-Result -description "Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable 'Allow Basic authentication' for WinRM Client" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowBasic /t REG_DWORD /d 0 /f
Add-Result -description "Disable 'Allow Basic authentication' for WinRM Client" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable 'Allow Basic authentication' for WinRM Service" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" /v AllowBasic /t REG_DWORD /d 0 /f
Add-Result -description "Disable 'Allow Basic authentication' for WinRM Service" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable running or installing downloaded software with invalid signature" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 0 /f
Add-Result -description "Disable running or installing downloaded software with invalid signature" -ok -changed

## --------

#Write-Host ($writeEmptyLine + "Set IPv6 source routing to highest protection" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
#reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

## --------

Write-Host ($writeEmptyLine + "Disable IP source routing" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
Add-Result -description "Disable IP source routing" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Block outdated ActiveX controls for Internet Explorer" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext" /v VersionCheckEnabled /t REG_DWORD /d 1 /f
Add-Result -description "Block outdated ActiveX controls for Internet Explorer" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable Solicited Remote Assistance" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
Add-Result -description "Disable Solicited Remote Assistance" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Disable Anonymous enumeration of shares" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
Add-Result -description "Disable Anonymous enumeration of shares" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Set 'Remote Desktop security level' to 'TLS'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f
Add-Result -description "Set 'Remote Desktop security level' to 'TLS" -ok -changed

## --------

Write-Host ($writeEmptyLine + "Set user authentication for remote connections by using Network Level Authentication to 'Enabled'" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f
Add-Result -description "Set user authentication for remote connections by using Network Level Authentication to 'Enabled'" -ok -changed

### !Attention only use when necessary 
    ### --------

#    Write-Host "Enable 'Microsoft network client: Digitally sign communications (always)'"
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

Write-Host ($writeEmptyLine + "ASR Rules AuditMode" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
#Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions AuditMode

Write-Host ($writeEmptyLine + "ASR Rules enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block abuse of exploited vulnerable signed drivers	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block executable content from email client and webmail	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block all Office applications from creating child processes" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block Office applications from creating executable content" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block Office applications from injecting code into other processes	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block JavaScript or VBScript from launching downloaded executable content	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block execution of potentially obfuscated scripts	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block Win32 API calls from Office macros	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Use advanced protection against ransomware	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block credential stealing from the Windows local security authority subsystem (lsass.exe)	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block process creations originating from PSExec and WMI commands	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block untrusted and unsigned processes that run from USB	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block Office communication application from creating child processes	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block Adobe Reader from creating child processes	" -ok -changed
Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled
Add-Result -description "ASR: Block persistence through WMI event subscription" -ok -changed
Set-MpPreference -EnableNetworkProtection Enabled
Add-Result -description "ASR: EnableNetworkProtection" -ok -changed
Set-MpPreference -PUAProtection Enabled
Add-Result -description "ASR: PUAProtection" -ok -changed
Set-MpPreference -MAPSReporting Advanced
Add-Result -description "ASR: MAPSReporting Advanced" -ok -changed
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Add-Result -description "ASR: SubmitSamplesConsent SendAllSamples" -ok -changed

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
        Set-LocalUser -Name "$NewLocalAdmin" -UserMayChangePassword:$false -PasswordNeverExpires:$true -AccountNeverExpires:$true
        Add-Result -description "$NewLocalAdmin local user created" -ok -changed
        Write-Verbose "$NewLocalAdmin local user created"

        if (Get-LocalGroup -Name "Administrators" -ErrorAction SilentlyContinue) {
            Add-LocalGroupMember -Group "Administrators" -Member "$NewLocalAdmin"
            Add-Result -description "$NewLocalAdmin added to the local Administrators group" -ok -changed
            Write-Verbose "$NewLocalAdmin added to the local Administrators group"
        }
        elseif (Get-LocalGroup -Name "Administratoren" -ErrorAction SilentlyContinue) {
            Add-LocalGroupMember -Group "Administratoren" -Member "$NewLocalAdmin"
            Add-Result -description "$NewLocalAdmin added to the local Administratoren group" -ok -changed
            Write-Verbose "$NewLocalAdmin added to the local Administratoren group"
        }else {
            Add-Result -description "$NewLocalAdmin is not in an Administrator Group" -failed
        }
    }    
    end {
    }
}

if ($AdminUsername) {

    Write-Host ($writeEmptyLine + "Creating local admin -> user set to:" + $AdminUsername + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine

    if ($AdminPassword) {
    [Security.SecureString]$securePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
    Write-Host ($writeEmptyLine + "Creating local admin -> password is set" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
        Add-LocalAdmin -NewLocalAdmin $AdminUsername -Password $securePassword -Verbose
        if ((Get-LocalUser $AdminUsername).count -eq 1) {
            Disable-LocalUser -Name aztmpadmin
            Add-Result -description "aztmpadmin is disabled" -ok -changed
        }
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
    Add-Result -description "AD-Connect downloaded and saved to: $outpath" -ok -changed


}
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Install Windows Features for Domain Controllers

if ($ADDomainServices) {
    
    Write-Host ($writeEmptyLine + "Install AD-Domain-Services" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
    Add-Result -description "Install AD-Domain-Services" -ok -changed

}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Extend Partition OS Drive

$driveLetter = "C"

$MaxSize = (Get-PartitionSupportedSize -DriveLetter $driveLetter).sizeMax
if ((get-partition -driveletter C).size -eq $MaxSize) {
    Write-Output "The drive $driveLetter is already at its maximum drive size"
    Add-Result -description "The drive $driveLetter is already at its maximum drive size" -ok 

}else {
    Resize-Partition -DriveLetter $driveLetter -Size $MaxSize
    Write-Output "The drive $driveLetter was already at its maximum drive size, nothing changed"
    Add-Result -description "The drive $driveLetter was already at its maximum drive size, nothing changed" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## BCEDIT

$hostname = "localhost"
Invoke-Command { Start-Process -wait -FilePath "cmd.exe"  -ArgumentList '/c "bcdedit /ems {current} on & bcdedit /emssettings EMSPORT:1 EMSBAUDRATE:115200 & bcdedit /set {bootmgr} displaybootmenu yes & bcdedit /set {bootmgr} timeout 30 & bcdedit /set {bootmgr} bootems yes"' } -ComputerName $hostname

Add-Result -description "Changed to recommended BCEDIT configuration" -ok -changed

Write-Host ($writeEmptyLine + "Changed to recommended BCEDIT configuration" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine


## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Firewall Policys with port 3389 (RDP)

$FireWall = New-Object -comObject HNetCfg.FwPolicy2
$EnableRules = $FireWall.rules | Where-Object {$_.LocalPorts -like "*3389*"}
ForEach ($Rule In $EnableRules){
    ($Rule.Enabled = "True")
}
Add-Result -description "Changed all Firewall Policys with Port 3389 (RDP) to enabled" -ok -changed

Write-Host ($writeEmptyLine + "Changed all Firewall Policys with Port 3389 (RDP) to enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine


## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Cleanup Script Logs

Write-Host ($writeEmptyLine + "# Cleanup Script Execution after reboot" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor1 $writeEmptyLine

# Get-ChildItem -Recurse -Path C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension -Include CustomScriptHandler.log | Remove-Item
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name 'DeleteLogCustomScript' -Value 'c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -noprofile -sta -command "Get-ChildItem -Recurse -Path C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension -Include CustomScriptHandler.log | Remove-Item"'

Add-Result -description "# Cleanup Script Execution after reboot" -ok -changed

## ------------

Stop-Transcript

## ------------

## Restart server to apply all changes, five seconds after running the last command

Write-Host ($writeEmptyLine + "# This server will restart to apply all changes" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor1 $writeEmptyLine

Start-Sleep -s 5
Restart-Computer -ComputerName localhost

