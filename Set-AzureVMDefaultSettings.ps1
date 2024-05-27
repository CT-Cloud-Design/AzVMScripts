<#
.SYNOPSIS
    A script used to set customized server settings on Azure Windows VMs running Windows Server 2016, Windows Server 2019 or Windows Server 2022.
.DESCRIPTION
    A script used to set customized server settings on Azure Windows VMs running Windows Server 2016, Windows Server 2019 or Windows Server 2022.
    This script will do all of the following:
    Autodetect Azure VMs
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
    Built-in Guest Account Not Renamed at Windows Target System
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
    Set default behavior for 'AutoRun' to 'Enabled: Do not4 execute any autorun commands
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
        Set Spooler Service Startup Type disabled
        Download AD-Connect Health Agent
    BCEDIT
    Firewall Policys with port 3389 (RDP)
    Set Pagefile to RamSize at B?S Azure VMs

    Restart the server to apply all changes, five seconds after running the last command.

    #Add later:
        ASR Action IDs prüfen == 1 indexof() -> ASR only possible without Temperprotection, try Intune or GPO intead.
        

.NOTES
    Disclaimer:     This script is provided "As Is" with no warranties.
	NAME: \Set-AzureVMDefaultSettings.ps1
	VERSION: 1.03
	AUTHOR: Ralf Bönisch - Cloud Design
    MAIL: rboenisch@cloud-design.de

    1.03:
    Add Domain Controller check for LSA

    1.02:
    Removed DisableNotifications ... Windows Firewall Bug ... Firewall Service invalid Data.
    Fixed bug with ASR enumeration when action and ids are empty.
.EXAMPLE
.\Set-AzureVMDefaultSettings.ps1
.\Set-AzureVMDefaultSettings.ps1 -AdminUsername "azadmin" -AdminPassword "password"
.\Set-AzureVMDefaultSettings.ps1 -ADDomainServices
    Install Domain-Controller Tools on Domain Controller (Switch)
    Download AD-Connect Health Agent
    Set Spooler Service Startup Type disabled
.\Set-AzureVMDefaultSettings.ps1 -ADConnect
    Automatic Download ADConnect
.\Set-AzureVMDefaultSettings.ps1 -dontStopProcessAndDontReboot
.\Set-AzureVMDefaultSettings.ps1 -NoASR
    without ASR Rules
.LINK
#>

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Parameters
Param(
    [string]$AdminUsername,
    [string]$AdminPassword,
    [switch]$ADDomainServices,
    [switch]$ADConnect,
    [switch]$dontStopProcessAndDontReboot,
    [switch]$NoASR
)

## Functions

$writeEmptyLine = "`n"
$writeSeperatorSpaces = " - "
$global:currenttime = Set-PSBreakpoint -Variable currenttime -Mode Read -Action {$global:currenttime= Get-Date -UFormat "%A %m/%d/%Y %R"}
#$foregroundColor1 = "Red"
$foregroundColor2 = "Yellow"

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
        Add-Content -Encoding UTF8 -Path "c:\temp\AzureVMDefaultSettingsResult.txt" -Value $newText
        Write-Host ($writeEmptyLine + $description + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine 
    }    
    end {
    }
}

function Set-RegistryDword {
    param (
        [string] $regPath,
        [string] $regKey,
        [string] $regValue,
        [string] $wasAllreadySetString,
        [string] $setString
    )
    
    try {
        if ((Get-ItemPropertyValue -Path $regPath -name $regKey -ErrorAction Stop) -ne $regValue) { throw "exception" }
        Add-Result -description $wasAllreadySetString -ok
    } catch {
        if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null}
        Set-ItemProperty -Path $regPath -name $regKey -Type DWord -Value $regValue | Out-Null
        Add-Result -description $setString -ok -changed
    }
}

function Get-isAzureVM () {
    try {
        $global:metadata = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -TimeoutSec 2
        Write-Host "azEnvironment: " $metadata.compute.azEnvironment
        Add-Result -description "azEnvironment: $($metadata.compute.azEnvironment)" -ok
        Write-Host "location: " $metadata.compute.location
        Add-Result -description "location: $($metadata.compute.location)" -ok
        Write-Host "name: " $metadata.compute.name
        Add-Result -description "name: $($metadata.compute.name)" -ok
        Write-Host "resourceGroupName: " $metadata.compute.resourceGroupName
        Add-Result -description "resourceGroupName: $($metadata.compute.resourceGroupName)" -ok
        Write-Host "vmSize: " $metadata.compute.vmSize
        Add-Result -description "vmSize: $($metadata.compute.vmSize)" -ok
        Write-Host "ipAddress: " $metadata.network.interface[0].ipv4.ipAddress
        Add-Result -description "ipAddress: $($metadata.network.interface[0].ipv4.ipAddress)" -ok
        return $true
    } catch {
        Write-Host "no Azure VM"
        return $false
    }
  }

  function Set-MpPreferenceAndReport {
    param (
        [string] $id,
        [string] $text
    )
    
    $ids = $global:mpPref.AttackSurfaceReductionRules_Ids
    $ids = [Collections.Generic.List[Object]]$ids
    $asrRulesAction = $global:mpPref.AttackSurfaceReductionRules_Actions
    
    if ($null -eq $asrRulesAction) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
        Add-Result -description "$text is now enabled" -ok -changed
        $global:mpPref = Get-MpPreference
        return
    }
    
    $position = $ids.FindIndex( {$args[0] -eq $id} )

    if ($position -ne -1) {
        if ($asrRulesAction[$position] = 1) {
            Add-Result -description "$text was already set to enabled" -ok
        } elseif ($asrRulesAction[$position] = 2) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
            Add-Result -description "$text was set audit and is now enabled" -ok -changed
        } elseif ($asrRulesAction[$position] = 0) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
            Add-Result -description "$text was set disabled and is now enabled" -ok -changed
        } else {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
            Add-Result -description "$text is now enabled" -ok -changed
        }
    } else {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
        Add-Result -description "$text" -ok -changed
    }
}

function Get-PageFile {
    <# 
     .SYNOPSIS
      List the drives that have page file(s) and their configuration 
    
     .DESCRIPTION
      List the drives that have page file(s) and their configuration 
      Note that 0 value for Initial or Maximum size indicate a system-managed page file
      This function does not require or accept any parameters
    
     .OUTPUTS 
      This function returns a PS object for each drive that has a page file on it,
      each having the following 3 properties/example:
        DriveLetter InitialSizeMB MaximumSizeMB
        ----------- ------------- -------------
                  C             0             0
                  D          1024          4096
    
    #>
    
        [CmdletBinding(ConfirmImpact='Low')] 
        Param()
    
        Begin { }
    
        Process {
            Get-WmiObject -Class Win32_PageFileSetting | 
                Select-Object  @{n='DriveLetter';  e={$_.Name[0]}},
                        @{n='InitialSizeMB';e={$_.InitialSize}},
                        @{n='MaximumSizeMB';e={$_.MaximumSize}}
            Write-Verbose '0 value for Initial or Maximum size indicate a system-managed page file'
        }
    
        End { }
}

function Set-PageFile {
    <# 
     .SYNOPSIS
      Function to set page file to be on a given drive 
    
     .DESCRIPTION
      Function to set page file to be on a given drive  
      Function will create page file if it does not exist on the provided drive
    
     .PARAMETER PageFile
      This is a PS Custom Object containing the following 3 properties:
        DriveLetter such as c
        InitialSizeMB such as 1024 (0 value indicate system managed page file)
        MaximumSizeMB such as 4096 (0 value indicate system managed page file)
      This object can be constructed manually as in:
      $PageFile = [PSCustomObject]@{
        DriveLetter   = 'c'
        InitialSizeMB = 0 
        MaximumSizeMB = 0 
      }
      or obtained from the Get-PageFile function of this PS module
    
     .EXAMPLE
      Set-PageFile -PageFile ([PSCustomObject]@{
        DriveLetter   = 'c'
        InitialSizeMB = 0 
        MaximumSizeMB = 0 
      })
      This example configures a system-managed page file on drive c
    
     .EXAMPLE
      Get-PageFile | ForEach-Object { $_.InitialSizeMB = 0; $_.MaximumSizeMB = 0; $_ } | Set-PageFile
      This example sets every page file to system-managed size
    
    #>


    [CmdletBinding(ConfirmImpact='Low')] 
    Param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)][PSCustomObject]$PageFile = [PSCustomObject]@{
            DriveLetter   = ((Get-WmiObject Win32_Volume | ForEach-Object PageFilePresent).DriveLetter | ForEach-Object { $_[0] } | Select-Object -First 1)
            InitialSizeMB = 0 # 0 = System Managed Size
            MaximumSizeMB = 0 # 0 = System Managed Size
        }
    )

    Begin { 
        Write-Verbose 'Input received:'
        Write-Verbose ($PageFile | Out-String)
        
        $DriveletterList = (Get-WmiObject Win32_Volume | Where-Object PageFilePresent).DriveLetter | ForEach-Object { $_[0] } 
        if ($PageFile.DriveLetter -notin $DriveletterList) {
            Write-Log 'Set-PageFile error:','Provided drive letter',$PageFile.DriveLetter,
                'does not exist on this computer, available drive letters are',($DriveletterList -join ', ') Magenta,Yellow,Magenta,Yellow,Magenta 
            break
        } else {
            Write-Verbose "Validated that provided drive letter '$($PageFile.DriveLetter)' exists on this computer '$($env:COMPUTERNAME)'"
        }
    }

    Process {

        $CurrentPageFile = Get-PageFile | Where-Object { $_.DriveLetter -match $PageFile.DriveLetter }
        if ($CurrentPageFile.InitialSizeMB -eq $PageFile.InitialSizeMB -and $CurrentPageFile.MaximumSizeMB -eq $PageFile.MaximumSizeMB) {
            Write-Log 'Existing page file',($CurrentPageFile | Out-String),'already matches provided parameters' Green,Yellow,Green
        } else {
            Write-Log 'Updating page file',($CurrentPageFile | Out-String) Green,Cyan

            #region Disable AutomaticManagedPagefile feature
            $compObj = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
            if ($compObj.AutomaticManagedPagefile) {
                $compObj.AutomaticManagedPagefile = $false
                $compObj.Put() | Out-Null
                $compObj = Get-WmiObject -Class Win32_compObj -EnableAllPrivileges
                if ($compObj.AutomaticManagedPagefile) { 
                    Write-Log 'Set-PageFile:','Unable to Disable AutomaticManagedPagefile feature','Get-WmiObject -Class Win32_compObj' Magenta,Yellow,Magenta
                    break
                } else {
                    Write-Log 'Disabled','AutomaticManagedPagefile','feature on',$compObj.Name Green,Cyan,Green,Cyan
                }
            } else {
                Write-Log 'Computer',$compObj.Name,'AutomaticManagedPagefile','feature is already disabled' Green,Cyan,Green,Cyan
            }
            #endregion

            # Change/Create Page File
            $pageFileSetting = Get-WmiObject -Class Win32_PageFileSetting | Where-Object { $_.Name.StartsWith($PageFile.DriveLetter) }
            if (-not $pageFileSetting) {
                Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{
                    Name        = "$($PageFile.DriveLetter):\pagefile.sys"
                    InitialSize = 0
                    MaximumSize = 0
                } -EnableAllPrivileges | Out-Null
                $pageFileSetting = Get-WmiObject -Class Win32_PageFileSetting | Where-Object { $_.Name.StartsWith($PageFile.DriveLetter) }
            }
            $pageFileSetting.InitialSize = $PageFile.InitialSizeMB
            $pageFileSetting.MaximumSize = $PageFile.MaximumSizeMB
            $pageFileSetting.Put() | Out-Null
            $CurrentPageFile = Get-PageFile | Where-Object { $_.DriveLetter -match $PageFile.DriveLetter }
            Write-Verbose 'PageFile setting:'
            Write-Verbose ($PageFile | Out-String)
            Write-Verbose 'CurrentPageFile setting:'
            Write-Verbose ($CurrentPageFile | Out-String)
            if ($CurrentPageFile.InitialSizeMB -eq $PageFile.InitialSizeMB -and $CurrentPageFile.MaximumSizeMB -eq $PageFile.MaximumSizeMB) {
                Write-Log 'Successfully updated page file settings to',($CurrentPageFile | Out-String) Green,Cyan
                Write-Log 'Remember that a reboot is required to complete this process' Yellow
            } else {
                Write-log 'Unable to change Page File setting',($CurrentPageFile | Out-String) Magenta,Yellow
            }
        }

    }

    End { }

}

function Remove-PageFile {
<# 
 .SYNOPSIS
  Function to remove page file from a given drive 

 .DESCRIPTION
  Function to remove page file from a given drive

 .PARAMETER DriveLetter
  Drive such as 'c' or 'e' that has a page file to be removed

 .EXAMPLE
  Remove-PageFile 'c'

 .LINK
  https://superwidgets.wordpress.com/category/powershell/

 .NOTES
  Function by Sam Boutros
  20 September 2018 - v0.1

#>

    [CmdletBinding(ConfirmImpact='Low')] 
    Param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
            [String]$DriveLetter = ((Get-WmiObject Win32_Volume | Where-Object PageFilePresent).DriveLetter | ForEach-Object { $_[0] } | Select-Object -First 1)
    )

    Begin { 
        Write-Verbose "Input received: DriveLetter $DriveLetter"
        
        $DriveletterList = (Get-WmiObject Win32_Volume | Where-Object PageFilePresent).DriveLetter | ForEach-Object { $_[0] } 
        if ($DriveLetter -notin $DriveletterList) {
            Write-Log 'Remove-PageFile error:','Provided drive letter',$DriveLetter,
                'does not exist on this computer, available drive letters are',($DriveletterList -join ', ') Magenta,Yellow,Magenta,Yellow,Magenta 
            break
        } else {
            Write-Verbose "Validated that provided drive letter '$($DriveLetter)' exists on this computer '$($env:COMPUTERNAME)'"
        }
    }

    Process { 
        Write-Log 'Current page file(s):', (Get-PageFile|Out-String) Green,Cyan 

        if ($DriveLetter -in (Get-PageFile).DriveLetter) {
            (Get-WmiObject -Class Win32_PageFileSetting | ForEach-Object { $_.Name.StartsWith($DriveLetter) }).Delete()
            Write-Log 'Removed page file from drive',$DriveLetter Green,Cyan
            Write-Log 'Current page file(s):', (Get-PageFile|Out-String) Green,Cyan 
            Write-Log 'Remember that a reboot is required to complete this process' Yellow
        } else {
            Write-Log 'No page file found on drive',$DriveLetter Yellow,Cyan
        }
    }

    End { }

}

## Result-File

Set-Content -Encoding UTF8 -Path "c:\temp\AzureVMDefaultSettingsResult.txt" -Value "" 
Add-Content -Encoding UTF8 -Path "c:\temp\AzureVMDefaultSettingsResult.txt" -Value " C O F  # Changed | OK | Failed"

## Variables

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$secCurrentContext = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$isSystem = ($secCurrentContext -like "*SYSTEM")
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
$isAzureVm = Get-isAzureVM
$computerType = ""

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Checks kind of computer

$productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
$compName = $env:COMPUTERNAME
switch ($productType)
{
    1 {"$compName is a workstation.";$computerType ="workstation"; break}
    2 {"$compName is a domain controller.";$computerType ="domain controller"; break}
    3 {"$compName is a server.";$computerType ="server"; break}

}

Add-Result -description "# $compName is a $computerType" -ok

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Create the folders, if it does not exist.

if (!(test-path $tempFolder))
{
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
    Add-Result -description "# $tempFolder folder created" -changed -ok
}
else {
    Add-Result -description "# $tempFolder folder exists" -ok
}

## ------------

if (!(test-path $installFolder))
{
    New-Item -ItemType Directory -Path $installFolder -Force | Out-Null
    Add-Result -description "# $installFolder folder created" -changed -ok
}
else {
    Add-Result -description "# $installFolder folder exists" -ok
}

## ------------

if (!(test-path $scriptsFolder))
{
    New-Item -ItemType Directory -Path $scriptsFolder -Force | Out-Null
    Add-Result -description "# $scriptsFolder folder created" -changed -ok
}
else {
    Add-Result -description "# $scriptsFolder folder exists" -ok
}

Start-Transcript -OutputDirectory "C:\Temp\"

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Debug

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

$allowIcmpV4FirewallRuleName = "Allow_Ping1_ICMPv4" # ICMPv4 Firewall Rule Name
$allowIcmpV4FirewallRuleDisplayName = "Allow Ping1 ICMPv4" # ICMPv4 Firewall Rule Display Name
$allowIcmpV4FirewallRuleDescription = "Packet Internet1 ICMPv4"

# Allow ICMP IPv4
try {
    Get-NetFirewallRule -Name $allowIcmpV4FirewallRuleName -ErrorAction Stop | Out-Null
    Add-Result -description "# Allow ICMP (ping) through Windows Firewall for IPv4 was ok" -ok
} catch {
    New-NetFirewallRule -Name $allowIcmpV4FirewallRuleName -DisplayName $allowIcmpV4FirewallRuleDisplayName -Description $allowIcmpV4FirewallRuleDescription -Protocol ICMPv4 -IcmpType 8 `
    -Enabled True -Profile Any -Action Allow | Out-Null
    Add-Result -description "# Allowed ICMP (ping) through Windows Firewall for IPv4" -ok -changed
}

$allowIcmpV6FirewallRuleName = "Allow_Ping1_ICMPv6" # ICMPv6 Firewall Rule Name
$allowIcmpV6FirewallRuleDisplayName = "Allow Ping1 ICMPv6" # ICMPv6 Firewall Rule Display Name
$allowIcmpV6FirewallRuleDescription = "Packet Internet1 ICMPv6"

# Allow ICMP IPv6
try {
    Get-NetFirewallRule -Name $allowIcmpV6FirewallRuleName -ErrorAction Stop | Out-Null
    Add-Result -description "# Allow ICMP (ping) through Windows Firewall for IPv6 was ok" -ok
} catch {
    New-NetFirewallRule -Name $allowIcmpV6FirewallRuleName -DisplayName $allowIcmpV6FirewallRuleDisplayName -Description $allowIcmpV6FirewallRuleDescription -Protocol ICMPv6 -IcmpType 8 `
    -Enabled True -Profile Any -Action Allow | Out-Null
    Add-Result -description "# Allowed ICMP (ping) through Windows Firewall for IPv6" -ok -changed
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
    Add-Result -description "# Remote Desktop was already enabled" -ok
} catch {
    Set-NetFirewallRule -DisplayName $allowRdpDisplayName -Enabled true -PassThru | Out-Null
    Add-Result -description "# Remote Desktop is now enabled" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enable secure RDP authentication Network Level Authentication (NLA)

$rdpRegKeyPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$rdpRegKeyName = "UserAuthentication"

try {
    if ((Get-ItemPropertyValue -Path $rdpRegKeyPath -name $rdpRegKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
    Add-Result -description "# Secure RDP authentication Network Level Authentication was already enabled" -ok
} catch {
    if (!(Test-Path $rdpRegKeyPath)) { New-Item -Path $rdpRegKeyPath -Force | Out-Null}
    Set-ItemProperty -Path $rdpRegKeyPath -name $rdpRegKeyName -Value 1 | Out-Null
    Add-Result -description "# Secure RDP authentication Network Level Authentication enabled" -ok -changed
}

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

try {
    if ((Get-ItemPropertyValue -Path $uacRegKeyPath -name $uacRegKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
    Add-Result -description "# User Access Control (UAC) was already enabled" -ok
} catch {
    if (!(Test-Path $uacRegKeyPath)) { New-Item -Path $uacRegKeyPath -Force | Out-Null}
    Set-ItemProperty -Path $uacRegKeyPath -Name $uacRegKeyName -Value 1 -Type DWord | Out-Null
    Add-Result -description "# User Access Control (UAC) enabled" -ok -changed
}
 
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable RDP printer mapping

$rdpPrinterMappingRegKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$rdpPrinterMappingRegKeyName = "fDisableCpm"

try {
    if ((Get-ItemPropertyValue -Path $rdpPrinterMappingRegKeyPath -name $rdpPrinterMappingRegKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
    Add-Result -description "# RDP printer mapping was already disabled" -ok
} catch {
    if (!(Test-Path $rdpPrinterMappingRegKeyPath)) { New-Item -Path $rdpPrinterMappingRegKeyPath -Force | Out-Null}
    Set-ItemProperty -Path $rdpPrinterMappingRegKeyPath -Name $rdpPrinterMappingRegKeyName -Value 1 | Out-Null
    Add-Result -description "# RDP printer mapping disabled" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable IE security for Administrators

$adminIESecurityRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$adminIESecurityRegKeyName = "IsInstalled"

try {
    if ((Get-ItemPropertyValue -Path $adminIESecurityRegKeyPath -name $adminIESecurityRegKeyName -ErrorAction Stop) -ne 0) { throw "exception" }
    Add-Result -description "# IE Enhanced Security Configuration for the Administrator was already disabled" -ok
} catch {
    if (!(Test-Path $adminIESecurityRegKeyPath)) { New-Item -Path $adminIESecurityRegKeyPath -Force | Out-Null}
    Set-ItemProperty -Path $adminIESecurityRegKeyPath -Name $adminIESecurityRegKeyName -Value 0 | Out-Null
    Add-Result -description "# IE Enhanced Security Configuration for the Administrator disabled" -ok -changed

    # Stop and start Windows explorer process
    if (!$isSystem) {
        # Stop and start Windows explorer process
        if (!$dontStopProcessAndDontReboot) {
            Stop-Process -processname $windowsExplorerProcessName -Force | Out-Null
        }
    }
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Windows Admin Center pop-up

$serverManagerRegKeyPath = "HKLM:\SOFTWARE\Microsoft\ServerManager"
$wacPopPupKeyName = "DoNotPopWACConsoleAtSMLaunch"

try {
    if ((Get-ItemPropertyValue -Path $serverManagerRegKeyPath -name $wacPopPupKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
    Add-Result -description "# Windows Admin Center pop-up was already disabled" -ok
} catch {
    if (!(Test-Path $serverManagerRegKeyPath)) { New-Item -Path $serverManagerRegKeyPath -Force | Out-Null}
    Set-ItemProperty -Path $serverManagerRegKeyPath -Name $wacPopPupKeyName -Value 1 | Out-Null
    Add-Result -description "# Windows Admin Center pop-up disabled" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Server Manager at logon

$task = Get-ScheduledTask -TaskName $scheduledTaskNameServerManager
if ($task.State -eq "Disabled") {
    Add-Result -description "# Server Manager was already disabled at startup" -ok
} else {
    $task | Disable-ScheduledTask | Out-Null
    Add-Result -description "# Server Manager disabled at startup" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable guest account

if (Get-LocalUser -Name "Gast" -ErrorAction SilentlyContinue) {
    $isDisabled = Get-WmiObject Win32_UserAccount -Computer localhost -Filter "Name = 'Gast'" | Select-Object Name,Disabled
    if ($isDisabled) {
        Add-Result -description "# Gast account was already disabled" -ok
    } else {
        net user guest /active:no | Out-Null
        Add-Result -description "# Gast account disabled" -ok -changed
    }
}

if (Get-LocalUser -Name "Gast" -ErrorAction SilentlyContinue) {
    $isDisabled = Get-WmiObject Win32_UserAccount -Computer localhost -Filter "Name = 'Guest'" | Select-Object Name,Disabled
    if ($isDisabled) {
        Add-Result -description "# Guest account was already disabled" -ok
    } else {
        net user guest /active:no | Out-Null
        Add-Result -description "# Guest account disabled" -ok -changed
    }
}

if (Get-LocalUser -Name "Besucher" -ErrorAction SilentlyContinue) {
    $isDisabled = Get-WmiObject Win32_UserAccount -Computer localhost -Filter "Name = 'Besucher'" | Select-Object Name,Disabled
    if ($isDisabled) {
        Add-Result -description "# Besucher account was already disabled" -ok
    } else {
        net user guest /active:no | Out-Null
        Add-Result -description "# Besucher account disabled" -ok -changed
    }
}


## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Hibernation

$hibernateRegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
$hibernateKeyName = "HibernateEnabled"

try {
    if ((Get-ItemPropertyValue -Path $hibernateRegKeyPath -name $hibernateKeyName -ErrorAction Stop) -ne 0) { throw "exception" }
    Add-Result -description "# Hibernation was already disabled" -ok
} catch {
    powercfg.exe /h off
    Add-Result -description "# Hibernation disabled" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Windows Diagnostic level (Telemetry) to Security (no Windows diagnostic data will be sent)

$windowsDiagnosticLevelRegKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$windowsDiagnosticLevelRegKeyName = "AllowTelemetry"

try {
    if ((Get-ItemPropertyValue -Path $windowsDiagnosticLevelRegKeyPath -name $windowsDiagnosticLevelRegKeyName -ErrorAction Stop) -ne 0) { throw "exception" }
    Add-Result -description "# Windows Diagnostic level (Telemetry) was already set to Security" -ok
} catch {
    New-Item $windowsDiagnosticLevelRegKeyPath -Force | Out-Null
    New-ItemProperty -Path $windowsDiagnosticLevelRegKeyPath -Name $windowsDiagnosticLevelRegKeyName -PropertyType "DWord" -Value 0 -Force | Out-Null
    Add-Result -description "# Windows Diagnostic level (Telemetry) set to Security" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set the Interactive Login to "Do not display the last username"

$interActiveLogonRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$interActiveLogonRegKeyName = "DontDisplayLastUsername"

try {
    if ((Get-ItemPropertyValue -Path $interActiveLogonRegKeyPath -name $interActiveLogonRegKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
    Add-Result -description "# Interactive Login was already set to - Do not display last user name" -ok
} catch {
    if (!(Test-Path $interActiveLogonRegKeyPath)) { New-Item -Path $interActiveLogonRegKeyPath -Force | Out-Null}
    Set-ItemProperty -Path $interActiveLogonRegKeyPath -Name $interActiveLogonRegKeyName -Value 1 | Out-Null
    Add-Result -description "# Interactive Login set to - Do not display last user name" -ok -changed
}
## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Folder Options

$folderOptionsRegKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" # Per Default User 

if ($isSystem) {
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
    $wasChangedFolderOptions = $true
}

try {
    if ((Get-ItemPropertyValue -Path $folderOptionsRegKeyPath -name $folderOptionsHiddenRegKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
} catch {
    Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsHiddenRegKeyName -Value 1 | Out-Null
    $wasChangedFolderOptions = $true
}
try {
    if ((Get-ItemPropertyValue -Path $folderOptionsRegKeyPath -name $folderOptionsHideFileExtRegKeyName -ErrorAction Stop) -ne 0) { throw "exception" }
} catch {
    Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsHideFileExtRegKeyName -Value 0 | Out-Null
    $wasChangedFolderOptions = $true
}
try {
    if ((Get-ItemPropertyValue -Path $folderOptionsRegKeyPath -name $folderOptionsShowSuperHiddenRegKeyName -ErrorAction Stop) -ne 0) { throw "exception" }
} catch {
    Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsShowSuperHiddenRegKeyName -Value 0 | Out-Null
    $wasChangedFolderOptions = $true
}
try {
    if ((Get-ItemPropertyValue -Path $folderOptionsRegKeyPath -name $folderOptionsHideDrivesWithNoMediaRegKeyName -ErrorAction Stop) -ne 0) { throw "exception" }
} catch {
    Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsHideDrivesWithNoMediaRegKeyName -Value 0 | Out-Null
    $wasChangedFolderOptions = $true
}
try {
    if ((Get-ItemPropertyValue -Path $folderOptionsRegKeyPath -name $folderOptionsSeperateProcessRegKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
} catch {
    Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsSeperateProcessRegKeyName -Value 1 | Out-Null
    $wasChangedFolderOptions = $true
}
try {
    if ((Get-ItemPropertyValue -Path $folderOptionsRegKeyPath -name $folderOptionsAlwaysShowMenusRegKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
} catch {
    Set-ItemProperty -Path $folderOptionsRegKeyPath -Name $folderOptionsAlwaysShowMenusRegKeyName -Value 1 | Out-Null
    $wasChangedFolderOptions = $true
}

if ($isSystem) {
    reg unload HKLM\DefaultUser
} else {
    # Stop and start Windows explorer process
    if (!$dontStopProcessAndDontReboot) {
        Stop-Process -processname $windowsExplorerProcessName -Force | Out-Null
    }
}

if ($wasChangedFolderOptions) {
    Add-Result -description "# Folder Options set" -ok -changed
} else {
    Add-Result -description "# Folder Options where already set" -ok
}



## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set volume label of C: to OS

$drive = Get-WmiObject win32_volume -Filter "DriveLetter = 'C:'"
if ($drive.Label -eq $cDriveLabel ) {
    Add-Result -description "# Volumelabel of C: was already set to $cDriveLabel" -ok
}else {
    $drive.Label = $cDriveLabel
    $drive.put() | Out-Null
    Add-Result -description "# Volumelabel of C: set to $cDriveLabel" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Time Zone (UTC+01:00)

$currentTimezone = Get-TimeZone
if ($currentTimezone.Id -eq $timezone) {
    Add-Result -description "# Timezone was already set to $timezone" -ok
} else {
    Set-TimeZone -Name $timezone
    Add-Result -description "# Timezone set to $timezone" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Power Management to High Performance, if it is not currently the active plan

try {
    $highPerf = powercfg -l | ForEach-Object {if($_.contains($powerManagement)) {$_.split()[3]}}
    $currPlan = $(powercfg -getactivescheme).split()[3]
    if ($currPlan -ne $highPerf) {
        powercfg -setactive $highPerf
        Add-Result -description "# Power Management set to $powerManagement" -ok -changed
    }else {
        Add-Result -description "# Power Management $currPlan was already set to $powerManagement" -ok 
    }
    
} catch {
    Write-Warning -Message ($writeEmptyLine + "# Unable to set power plan to $powerManagement" + $writeSeperatorSpaces + $currentTime + $writeEmptyLine) 
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
} else {
        Add-Result -description "# Keybord all ready set to German" -ok
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Built-in Guest Account Not Renamed at Windows Target System

if ($localUser = Get-LocalUser -Name "Besucher" -ErrorAction SilentlyContinue) {
    if ($localUser.description -ne "") {
        Set-LocalUser $localUser -Description ""
        Add-Result -description "# Built-in Guest Account: Besucher description was removed" -ok -changed
    }
    Add-Result -description "# Built-in Guest Account was already renamed to Besucher" -ok
}

$users = @("Gast","Guest")

$users | ForEach-Object {
    if (Get-LocalUser -Name $_ -ErrorAction SilentlyContinue) {
        Rename-LocalUser -Name $_ -NewName "Besucher"
        Set-LocalUser -Name "Besucher" -Description "" 
        Add-Result -description "# Built-in $_ Account renamed to Besucher" -ok -changed
    }
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Remove description of the Local Administrator Account
$users = @("aztmpadmin","azadmin","Administrator")

$users | ForEach-Object {
    if ($localUser = Get-LocalUser -Name $_ -ErrorAction SilentlyContinue) {
        if ($localUser.description -eq "") {
            Add-Result -description "# Description was already removed from Local $_ Account" -ok
        } else {
            Set-LocalUser -Name $_ -Description ""
            Add-Result -description "# Description removed from Local $_ Account" -ok -changed
        }   
    }
}



## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disable Automount

$automountRegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mountmgr"
$automountRegKeyName = "NoAutoMount"

try {
    if ((Get-ItemPropertyValue -Path $automountRegKeyPath -name $automountRegKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
    Add-Result -description "# Automount Disabled was already disabled" -ok
} catch {
    if (!(Test-Path $automountRegKeyPath)) { New-Item -Path $automountRegKeyPath -Force | Out-Null}
    Set-ItemProperty -Path $automountRegKeyPath -name $automountRegKeyName -Value 1 | Out-Null
    Add-Result -description "# Automount Disabled" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## IPv4 before IPv6

$ipv4v6RegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$ipv4v6RegKeyName = "DisabledComponents"

try {
    if ((Get-ItemPropertyValue -Path $ipv4v6RegKeyPath -name $ipv4v6RegKeyName -ErrorAction Stop) -ne 32) { throw "exception" }
    Add-Result -description "# IPv4 before IPv6 was already enabled" -ok
} catch {
    New-Item $ipv4v6RegKeyPath -Force | Out-Null
    New-ItemProperty -Path $ipv4v6RegKeyPath -name $ipv4v6RegKeyName -PropertyType DWORD -Value "0x20" | Out-Null
    Add-Result -description "# IPv4 before IPv6 is now enabled" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Hardening

$cfaKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$cfaKeyName = "EnableControlledFolderAccess"

try {
    if ((Get-ItemPropertyValue -Path $cfaKeyPath -name $cfaKeyName -ErrorAction Stop) -ne 2) { throw "exception" }
    Add-Result -description "# Controlled folder access was already set to audit mode" -ok
} catch {
    if ($computerType -eq "domain controller") {
        Add-Result -description "# Skipped DC: Set controlled folder access to audit mode" -ok
    }else {
        New-Item $cfaKeyPath -Force | Out-Null
        New-ItemProperty -Path $cfaKeyPath -name $cfaKeyName -PropertyType DWORD -Value 2 | Out-Null
        Add-Result -description "# Set controlled folder access to audit mode" -ok -changed
    }
    
}

## --------

$lsaKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaKeyName = "RunAsPPL"

try {
    if ((Get-ItemPropertyValue -Path $lsaKeyPath -name $lsaKeyName -ErrorAction Stop) -ne 1) { throw "exception" }
    Add-Result -description "# Enable 'Local Security Authority (LSA) protection was already set" -ok
} catch {
    if ($computerType -eq "domain controller") {
        Add-Result -description "# Skipped DC: Enable 'Local Security Authority (LSA) protection" -ok
    }else {
        New-Item $lsaKeyPath -Force | Out-Null
        New-ItemProperty -Path $lsaKeyPath -name $lsaKeyName -PropertyType DWORD -Value 1 | Out-Null
        Add-Result -description "# Enable 'Local Security Authority (LSA) protection" -ok -changed
    }
}

## --------

$enumAdmAccKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
$enumAdmAccKeyKeyName = "EnumerateAdministrators"

try {
    if ((Get-ItemPropertyValue -Path $enumAdmAccKeyPath -name $enumAdmAccKeyKeyName -ErrorAction Stop) -ne 0) { throw "exception" }
    Add-Result -description "# Disable 'Enumerate administrator accounts on elevation was already set" -ok
} catch {
    New-Item $enumAdmAccKeyPath -Force | Out-Null
    New-ItemProperty -Path $enumAdmAccKeyPath -name $enumAdmAccKeyKeyName -PropertyType DWORD -Value 0 | Out-Null
    Add-Result -description "# Disable 'Enumerate administrator accounts on elevation" -ok -changed
}

## --------

# Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
# -regKey "DisableNotifications"  `
# -regValue 1  `
# -wasAllreadySetString "Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile was already set" `
# -setString "Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile"

# ## --------

# Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfiles" `
# -regKey "DisableNotifications"  `
# -regValue 1  `
# -wasAllreadySetString "Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile was already set" `
# -setString "Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile"

# ## --------

# Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" `
# -regKey "DisableNotifications"  `
# -regValue 1  `
# -wasAllreadySetString "Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile was already set" `
# -setString "Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile"

# Zum Änderungen Rückgängig machen:
# Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' -name "DisableNotifications"
# Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfiles' -name "DisableNotifications"
# Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -name "DisableNotifications"

# Firewallprofile deaktivieren für Troubleshooting:
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\DomainProfile' -name "EnableFirewall" -Value 0
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' -name "EnableFirewall" -Value 0
# Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\Standardprofile' -name "EnableFirewall" -Value 0 

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
-regKey "LocalAccountTokenFilterPolicy"  `
-regValue 0  `
-wasAllreadySetString "Enable 'Apply UAC restrictions to local accounts on network logons was already set" `
-setString "Enable 'Apply UAC restrictions to local accounts on network logons"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
-regKey "NC_AllowNetBridge_NLA"  `
-regValue 0  `
-wasAllreadySetString "Disable 'Installation and configuration of Network Bridge on your DNS domain network was already set" `
-setString "Disable 'Installation and configuration of Network Bridge on your DNS domain network"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
-regKey "NC_StdDomainUserSetLocation"  `
-regValue 1  `
-wasAllreadySetString "Enable 'Require domain users to elevate when setting a network's location was already set" `
-setString "Enable 'Require domain users to elevate when setting a network's location"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" `
-regKey "NC_ShowSharedAccessUI"  `
-regValue 0  `
-wasAllreadySetString "Prohibit use of Internet Connection Sharing on your DNS domain network was already set" `
-setString "Prohibit use of Internet Connection Sharing on your DNS domain network"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
-regKey "AlwaysInstallElevated"  `
-regValue 0  `
-wasAllreadySetString "Disable 'Always install with elevated privileges was already set" `
-setString "Disable 'Always install with elevated privileges"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
-regKey "NoAutoplayfornonVolume"  `
-regValue 1  `
-wasAllreadySetString "Disable 'Autoplay for non-volume devices was already set" `
-setString "Disable 'Autoplay for non-volume devices"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
-regKey "NoDriveTypeAutoRun"  `
-regValue 255  `
-wasAllreadySetString "Disable 'Autoplay' for all drives was already set" `
-setString "Disable 'Autoplay' for all drives"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
-regKey "NoAutorun"  `
-regValue 1  `
-wasAllreadySetString "Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands was already set" `
-setString "Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" `
-regKey "AllowBasic"  `
-regValue 0  `
-wasAllreadySetString "Disable 'Allow Basic authentication' for WinRM Client was already set" `
-setString "Disable 'Allow Basic authentication' for WinRM Client"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" `
-regKey "AllowBasic"  `
-regValue 0  `
-wasAllreadySetString "Disable 'Allow Basic authentication' for WinRM Service was already set" `
-setString "Disable 'Allow Basic authentication' for WinRM Service"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download" `
-regKey "RunInvalidSignatures"  `
-regValue 0  `
-wasAllreadySetString "Disable running or installing downloaded software with invalid signature was already set" `
-setString "Disable running or installing downloaded software with invalid signature"

## --------
<#
Set-RegistryDword -regPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
-regKey "DisableIPSourceRouting"  `
-regValue 2  `
-wasAllreadySetString "Set IPv6 source routing to highest protection was already set" `
-setString "Set IPv6 source routing to highest protection"
#>
## --------

Set-RegistryDword -regPath "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
-regKey "DisableIPSourceRouting"  `
-regValue 2  `
-wasAllreadySetString "Disable IP source routing was already set" `
-setString "Disable IP source routing"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext" `
-regKey "VersionCheckEnabled"  `
-regValue 1  `
-wasAllreadySetString "Block outdated ActiveX controls for Internet Explorer was already set" `
-setString "Block outdated ActiveX controls for Internet Explorer"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
-regKey "fAllowToGetHelp"  `
-regValue 0  `
-wasAllreadySetString "Disable Solicited Remote Assistance was already set" `
-setString "Disable Solicited Remote Assistance"

## --------

Set-RegistryDword -regPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
-regKey "RestrictAnonymous"  `
-regValue 1  `
-wasAllreadySetString "Disable Anonymous enumeration of shares was already set" `
-setString "Disable Anonymous enumeration of shares"

## --------

Set-RegistryDword -regPath "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
-regKey "SecurityLayer"  `
-regValue 2  `
-wasAllreadySetString "Set 'Remote Desktop security level' to 'TLS was already set" `
-setString "Set 'Remote Desktop security level' to 'TLS"

## --------

Set-RegistryDword -regPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
-regKey "UserAuthentication"  `
-regValue 1  `
-wasAllreadySetString "Set user authentication for remote connections by using Network Level Authentication to 'Enabled' was already set" `
-setString "Set user authentication for remote connections by using Network Level Authentication to 'Enabled'"

#reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Nt\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_DWORD /d 1 /f
#Add-Result -description "Enabled Cached Logon Credential" -ok -changed

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

    # Schedule Task gehen nicht mehr (außer System) + network authentication credentials
    #Write-Host "Disable the local storage of passwords and credentials"
#    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /t REG_DWORD /d 1 /f''

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## ASR-Rules

if (!$NoASR) {

    #Write-Host ($writeEmptyLine + "ASR Rules AuditMode" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    #Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions AuditMode

    $global:mpPref = Get-MpPreference

    Write-Host ($writeEmptyLine + "ASR Rules enabled" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    
    Set-MpPreferenceAndReport -id "56a863a9-875e-4185-98a7-b882c64b5ce5" -text "ASR: Block abuse of exploited vulnerable signed drivers"
    Set-MpPreferenceAndReport -id "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" -text "ASR: Block executable content from email client and webmail"
    Set-MpPreferenceAndReport -id "D4F940AB-401B-4EfC-AADC-AD5F3C50688A" -text "ASR: Block all Office applications from creating child processes"
    Set-MpPreferenceAndReport -id "3B576869-A4EC-4529-8536-B80A7769E899" -text "ASR: Block Office applications from creating executable content"
    Set-MpPreferenceAndReport -id "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" -text "ASR: Block Office applications from injecting code into other processes"
    Set-MpPreferenceAndReport -id "D3E037E1-3EB8-44C8-A917-57927947596D" -text "ASR: Block JavaScript or VBScript from launching downloaded executable content"
    Set-MpPreferenceAndReport -id "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" -text "ASR: Block execution of potentially obfuscated scripts"
    Set-MpPreferenceAndReport -id "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" -text "ASR: Block Win32 API calls from Office macros"
    Set-MpPreferenceAndReport -id "01443614-CD74-433A-B99E-2ECDC07BFC25" -text "ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
    Set-MpPreferenceAndReport -id "C1DB55AB-C21A-4637-BB3F-A12568109D35" -text "ASR: Use advanced protection against ransomware"
    Set-MpPreferenceAndReport -id "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" -text "ASR: Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
    Set-MpPreferenceAndReport -id "D1E49AAC-8F56-4280-B9BA-993A6D77406C" -text "ASR: Block process creations originating from PSExec and WMI commands"
    Set-MpPreferenceAndReport -id "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" -text "ASR: Block untrusted and unsigned processes that run from USB"
    Set-MpPreferenceAndReport -id "26190899-1602-49E8-8B27-EB1D0A1CE869" -text "ASR: Block Office communication application from creating child processes"
    Set-MpPreferenceAndReport -id "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -text "ASR: Block Adobe Reader from creating child processes"
    Set-MpPreferenceAndReport -id "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" -text "ASR: Block persistence through WMI event subscription"

    if ($mpPref.EnableNetworkProtection -eq 1) {
        Add-Result -description "ASR: EnableNetworkProtection was already enabled" -ok
    } else {
        Set-MpPreference -EnableNetworkProtection Enabled
        Add-Result -description "ASR: EnableNetworkProtection enabled" -ok -changed
    }
    
    if ($mpPref.PUAProtection -eq 1) {
        Add-Result -description "ASR: PUAProtection was already enabled" -ok
    } else {
        Set-MpPreference -PUAProtection Enabled
        Add-Result -description "ASR: PUAProtection enabled" -ok -changed
    }

    if ($mpPref.MAPSReporting -eq 2) {
        Add-Result -description "ASR: MAPSReporting Advanced was already enabled" -ok
    } else {
        Set-MpPreference -MAPSReporting Advanced
        Add-Result -description "ASR: MAPSReporting Advanced enabled" -ok -changed
    }

    if ($mpPref.SubmitSamplesConsent -eq 3) {
        Add-Result -description "ASR: Send all samples automatically was already enabled" -ok
    } else {
        Set-MpPreference -SubmitSamplesConsent SendAllSamples
        Add-Result -description "ASR: Send all samples automatically" -ok -changed
    }

    if ($mpPref.ScanScheduleQuickScanTime -eq "12:00:00") {
        Add-Result -description "Defender: QuickScan at 12:00:00 was already set" -ok
    } else {
        Set-MpPreference -ScanScheduleQuickScanTime 12:00:00
        Add-Result -description "Defender: Set QuickScan at 12:00:00" -ok -changed
    }
    
}


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

        if (Get-LocalGroup -Name "Administrators" -ErrorAction SilentlyContinue) {
            Add-LocalGroupMember -Group "Administrators" -Member "$NewLocalAdmin"
            Add-Result -description "$NewLocalAdmin added to the local Administrators group" -ok -changed
        }
        elseif (Get-LocalGroup -Name "Administratoren" -ErrorAction SilentlyContinue) {
            Add-LocalGroupMember -Group "Administratoren" -Member "$NewLocalAdmin"
            Add-Result -description "$NewLocalAdmin added to the local Administratoren group" -ok -changed
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
    Add-Result -description "AD-Domain-Services installed" -ok -changed

    Stop-Service -name Spooler -force
    Set-Service -name Spooler -startupType disabled
    Add-Result -description "Spooler Service Startup Type disabled" -ok -changed

    $ADConnectHealtURL = "https://go.microsoft.com/fwlink/?LinkID=820540"

    Write-Host ($writeEmptyLine + "Download AD-Connect Health Agent" + $writeSeperatorSpaces + $currentTime) -foregroundcolor $foregroundColor2 $writeEmptyLine
    $outpath = "C:\Install\AdHealthAddsAgentSetup.exe"
    Invoke-WebRequest $ADConnectHealtURL -UseBasicParsing -OutFile $outpath
    Add-Result -description "Download AD-Connect Health Agent downloaded and saved to: $outpath" -ok -changed

}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Extend Partition OS Drive

$driveLetter = "C"

$MaxSize = (Get-PartitionSupportedSize -DriveLetter $driveLetter).sizeMax
if ((get-partition -driveletter C).size -eq $MaxSize) {
    Add-Result -description "The drive $driveLetter is already at its maximum drive size" -ok 

}else {
    Resize-Partition -DriveLetter $driveLetter -Size $MaxSize
    Add-Result -description "The drive $driveLetter was already at its maximum drive size, nothing changed" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## BCEDIT

if ($isAzureVm) {
    
    $bcdOutput = (bcdedit /enum) -join "`n" # collect bcdedit's output as a *single* string
    $entries = New-Object System.Collections.Generic.List[pscustomobject]]
    ($bcdOutput -split '(?m)^(.+\n-)-+\n' -ne '').ForEach({
    if ($_.EndsWith("`n-")) { # entry header 
        $entries.Add([pscustomobject] @{ Name = ($_ -split '\n')[0]; Properties = [ordered] @{} })
    } else {  # block of property-value lines
        ($_ -split '\n' -ne '').ForEach({
        $propAndVal = $_ -split '\s+', 2 # split line into property name and value
        if ($propAndVal[0] -ne '') { # [start of] new property; initialize list of values
            $currProp = $propAndVal[0]
            $entries[-1].Properties[$currProp] = New-Object Collections.Generic.List[string]
        }
        $entries[-1].Properties[$currProp].Add($propAndVal[1]) # add the value
        })
    }
    })

    if ($entries[0].Properties.timeout -eq "30") {
        Add-Result -description "Azure Recommended BCEDIT configuration was already applied" -ok
    } else {
        Start-Process -wait -FilePath "cmd.exe"  -ArgumentList '/c "bcdedit /ems {current} on & bcdedit /emssettings EMSPORT:1 EMSBAUDRATE:115200 & bcdedit /set {bootmgr} displaybootmenu yes & bcdedit /set {bootmgr} timeout 30 & bcdedit /set {bootmgr} bootems yes"'
        Add-Result -description "Changed to Azure Recommended BCEDIT configuration" -ok -changed
    }

} else {
    Add-Result -description "No Azure VM: Did not change to Azure Recommended BCEDIT configuration" -ok -changed
}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Set Pagefile to RamSize at B?S Azure VMs


if ($isAzureVm) {
    
    $RAM = [Math]::Round((Get-WmiObject Win32_OperatingSystem).TotalVisibleMemorySize / 1kb)

    if ($metadata.compute.vmSize.ToLower() -match "b[0-9]s") {
    #BS VMSize

        Write-Host "b?s found"
    
        $pagefileD = Get-PageFile | Where-Object { $_.DriveLetter -match "d" }
        if ($pagefileD) {
            if ($pagefileD.InitialSizeMB -lt ($RAM + 1)) {
                $pagefileD.InitialSizeMB = $RAM + 1
                $pagefileD.MaximumSizeMB = $RAM + 1
                $volumeD = (get-volume d).SizeRemaining
                $volumeDinMB = [Math]::Round($volumeD / 1mb)
                if ($volumeDinMB -gt ($RAM + 1)) {
                    Set-PageFile -Pagefile $pagefileD
                    $description = "Pagefile changed to " + $pagefileD.MaximumSize + " : VMSize matches B[0-9]s"
                    Add-Result -description $description -ok -changed  
                } else {
                    Add-Result -description "Insufficient disk space on D: for Pagefile: $($pagefileD.MaximumSizeMB)" -failed
                }
            } else {
                Add-Result -description "Pagefile size was already correct" -ok
            }
        } else {
            Add-Result -description "No pagefile for D:\" -failed 
        }
    } elseif  ($metadata.compute.vmSize.ToLower() -match "b[0-9]ls_v2"){

        Write-Host "b[0-9]ls_v2 found"
        
        $pagefileC = Get-PageFile | Where-Object { $_.DriveLetter -match "c" }
        if ($pagefileC) {
            if ($pagefileC.InitialSizeMB -lt ($RAM + 1)) {
                $pagefileC.InitialSizeMB = $RAM + 1
                $pagefileC.MaximumSizeMB = $RAM + 1
                $volumeD = (get-volume d).SizeRemaining
                $volumeDinMB = [Math]::Round($volumeD / 1mb)
                if ($volumeDinMB -gt ($RAM + 1)) {
                    Set-PageFile -Pagefile $pagefileC
                    $description = "Pagefile changed to " + $pagefileC.MaximumSize + " : VMSize matches b[0-9]ls_v2"
                    Add-Result -description $description -ok -changed  
                } else {
                    Add-Result -description "Insufficient disk space on C: for Pagefile: $($pagefileC.MaximumSizeMB)" -failed
                }
            } else {
                Add-Result -description "Pagefile size was already correct" -ok
            }
        } else {
            Set-PageFile -PageFile ([PSCustomObject]@{
                DriveLetter   = 'c'
                InitialSizeMB = $RAM + 1 
                MaximumSizeMB = $RAM + 1 
              })
              $pagefileC = Get-PageFile | Where-Object { $_.DriveLetter -match "c" }
              if ($pagefileC) {
                Add-Result -description "New pagefile for C:\ was created!" -changed -ok 
              }else {
                Add-Result -description "No pagefile for C:\" -failed 
              }
            
        }
    } else {
        Add-Result -description "Azure VMSize mismatch for pagefile changes" -ok 
    }

}

## Format Disk1 (E:) to GPT 

if ($isAzureVm) {
    
    if ((get-disk 1).PartitionStyle -eq "RAW") {
        Initialize-Disk 1
        if ((get-disk 1).PartitionStyle -eq "GPT") {
            $description = "Disk 1 for E:\ changed to " + (get-disk 1).PartitionStyle + "."
                Add-Result -description $description -ok -changed  
        } else {
            Add-Result -description "Disk 1 for E:\ is $((get-disk 1).PartitionStyle)" -failed
        }
    } else {
        Add-Result -description "GPT Disk for E:\ was already correct" -ok 
    }

}

## Format Disk1 (E:) to NTFS 

if ($isAzureVm) {
    
    if ((get-disk 1).PartitionStyle -eq "GPT") {
        $partitions = (Get-Partition -DiskNumber 1)
        if ($partitions.type -eq "Basic") {
            Add-Result -description "Disk 1 has already a Basic Partition" ok
        } else {
            $newpartition = new-partition -disknumber 1 -AssignDriveLetter -usemaximumsize | format-volume -filesystem NTFS -newfilesystemlabel NTDS
            if ( $newpartition.DriveLetter -eq "E" ) {
                if ( $newpartition.HealthStatus -eq "Healthy" ) {
                    $description = "Disk 1 for E:\ formated and status is Healthy"
                    Add-Result -description $description -ok -changed 
                }else {
                    Add-Result -description "Disk 1 for E:\ formated but status is not Healthy" -failed
                }
            } else {
                Add-Result -description "Disk 1 formated but driveletter is not E:\" -failed
            }
            $description = "Disk 1 for E:\ changed to " + (get-disk 1).PartitionStyle + "."
            Add-Result -description $description -ok -changed 
        }
    } else {
        Add-Result -description "Disk 1 Format NTFS for E:\ PartitionStyle not GPT" -failed 
    }

}

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Firewall Policys with port 3389 (RDP)

$FireWall = New-Object -comObject HNetCfg.FwPolicy2
$EnableRules = $FireWall.rules | Where-Object {$_.LocalPorts -like "*3389*"}
$didChange = $false
ForEach ($Rule In $EnableRules){
    if (!$Rule.Enabled) {
        ($Rule.Enabled = "True")
        $didChange = $true
        Add-Result -description "Firewall Policy: $Rule.Name was changed to enabled" -ok -changed
    }
}
if (!$didChange) {
    Add-Result -description "All Firewall Policys with Port 3389 (RDP) where already enabled" -ok
}


## ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Cleanup Script Logs

Write-Warning ($writeEmptyLine + "# Cleanup Script Execution after reboot" + $writeSeperatorSpaces + $currentTime + $writeEmptyLine) 

$findings = Get-ChildItem -Recurse -Path C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension -Include CustomScriptHandler.log -ErrorAction SilentlyContinue

if ($findings) {
    Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name 'DeleteLogCustomScript' -Value 'c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -noprofile -sta -command "Get-ChildItem -Recurse -Path C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension -Include CustomScriptHandler.log | Remove-Item"'
    Add-Result -description "# Cleanup Script Execution after reboot" -ok -changed
} else {
    Add-Result -description "# Cleanup Script after reboot was not needed " -ok
}

## ------------

Stop-Transcript

## ------------

## Restart server to apply all changes, five seconds after running the last command

Write-Warning ($writeEmptyLine + "# This server will restart to apply all changes" + $writeSeperatorSpaces + $currentTime + $writeEmptyLine) 
if (!$dontStopProcessAndDontReboot) {
    Start-Sleep -s 5
    Restart-Computer -ComputerName localhost
}


