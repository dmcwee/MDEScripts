<#
=============================================================================

=============================================================================

#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory=$true, HelpMessage='List of machines to check for MDE readiness')][string[]]$Machines
)

<#
    This function will perform client checks of the defender service but is not currently used.
#>
function Get-ClientMdeInstalledStatus {
    param(
        [string]$MachineName
    )

    Get-WindowsOptionalFeature -Online | Where -Property FeatureName -like "*efender*"
}

function Get-ServerMdeInstalledStatus {
    param (
        [string]$MachineName
    )

    (Get-WindowsFeature -Name Windows-Defender -ComputerName $MachineName).Installed
}

function Get-RemoteRegistryValue {
    param(
        [string]$MachineName,
        [string]$RegKeyPath,
        [string]$RegKeyName
    )

    $r = Invoke-Command -ComputerName $MachineName -ScriptBlock { Get-ItemProperty -Path $Using:RegKeyPath -Name $Using:RegKeyName -ErrorAction SilentlyContinue }
    Write-Debug ("Machine {0} '{1}:{2} value is {3}" -f $MachineName, $RegKeyPath, $RegKeyName, $r.$RegKeyName)
    $r.$RegKeyName
}

<#
    This aligns with the GPO Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> Real-time Protection >> Turn off real-time protection
    and the GPO Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> Turn off Windows Defender Antivirus
#>
function Get-DisableAntiSpywareSetting {
    param (
        [string]$MachineName
    )

    #look at HybridModeEnabled as well to determine what it means
    $s = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath 'HKLM:\Software\Microsoft\Windows Defender' -RegKeyName DisableAntiSpyware
    $p = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath 'HKLM:\Software\Policies\Microsoft\Windows Defender' -RegKeyName DisableAntiSpyware

    $p -or $s
}

<#
    This appears to be replaced by the GPO to 'Turn off Windows Defender Antivirus'
#>
function Get-DisableAntiVirusSetting {
    param (
        [string]$MachineName
    )

    $s = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath 'HKLM:\Software\Microsoft\Windows Defender' -RegKeyName DisableAntiVirus
    $s
}

function Get-DisableRealTimeMonitoring {
    param (
        [string]$MachineName
    )

    $s = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath 'HKLM:\Software\Microsoft\Windows Defender\Real-Time Protection' -RegKeyName DisableRealtimeMonitoring
    $p = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -RegKeyName DisableRealtimeMonitoring
    $s -or $p
}

function Get-ForcePassiveMode {
    param (
        [string]$MachineName
    )

    $p = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' -RegKeyName ForceDefenderPassiveMode
    $p
}

<#
    This aligns with the GPO Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> Turn off Windows Defender Antivirus
#>
function Get-DpaDisabled {
    param (
        [string]$MachineName
    )

    $s = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' -RegKeyName DpaDisabled
    $s

    #$p = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' -RegKeyName DpaDisabled
    #$p -or $s
}

function Get-DisableOnAccessProtection {
    param (
        [string]$MachineName
    )

    $p = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -RegKeyName DisableOnAccessProtection
    $p
}

function Get-Win2012R2Update {
    param (
        [string]$MachineName
    )

    try {
        $update = Get-HotFix -id "KB3045999" -ComputerName $MachineName
    }
    catch {
        write-debug ("Get-Win2012R2Update: Error caught calling Get-HotFix to remote machine {0}. Reverting to Invoke-Command." -f $MachineName)
        $update = Invoke-Command -ComputerName $MachineName -ScriptBlock { Get-HotFix -id "KB3045999" }
    }
    
    $update | format-list -property *
    $update
}

<#
    Refer to https://msrc.microsoft.com/update-guide/vulnerability/ADV990001 for Servicing Stack Updates
    Then navigate to the MS Catalog for the latest list of SSUs and check if there are additional items that 
    supercede these KBs.
#>
function Get-Win2016Update {
    param (
        [string]$MachineName
    )

    # As of 1 Sept 2023 these are the correct KBs
    $SSUKbs = @'
    Date, Description, HotFixID
    2021-09, Servicing Stack Update for Windows Server 2016 for x64-based Systems, KB5005698
    2022-03, Servicing Stack Update for Windows Server 2016 for x64-based Systems, KB5011570
    2022-05, Servicing Stack Update for Windows Server 2016 for x64-based Systems, KB5014026
    2022-07, Servicing Stack Update for Windows Server 2016 for x64-based Systems, KB5016058
    2022-08, Servicing Stack Update for Windows Server 2016 for x64-based Systems, KB5017095
    2022-09, Servicing Stack Update for Windows Server 2016 for x64-based Systems, KB5017396
    2023-03, Servicing Stack Update for Windows Server 2016 for x64-based Systems, KB5023788
'@ | ConvertFrom-Csv | Select-object -ExpandProperty HotFixID

    try {
        $update = Get-HotFix -id $SSUKbs -ComputerName $MachineName
    }
    catch {
        write-debug ("Get-Win2016Update: Error caught calling Get-HotFix to remote machine {0}. Reverting to Invoke-Command." -f $MachineName)
        $update = Invoke-Command -ComputerName $MachineName -ScriptBlock { Get-HotFix -id $Using:SSUKbs }
    }
    
    $update | format-list -property *
    $update
}

<#
    Get-ADComputer will return a value like:
      "Microsoft Windows Server 2012 R2 Datacenter"
      "Microsoft Windows Server 2019 Datacenter"

    Get-WmiObject will return a value like:
      "Microsoft Windows Server 2012 R2 Datacenter"
      "Microsoft Windows Server 2019 Datacenter"

    Get-ComputerInfo will return a value like:
      "Windows Server 2019 Datacenter"
      "Windows Server 2016 Datacenter"
#>
function Get-WindowsVersion {
    param(
        [string]$MachineName
    )

    # Best way to detect systems is from a machine with PowerShell AD. In case that is not possible catch the error and move to other methods
    try {
        $caption = Get-ADComputer -Filter {(Name -eq $MachineName)} -Properties OperatingSystem,OperatingSystemVersion -ErrorAction SilentlyContinue
    }
    catch {
        $caption = $null
    }
    
    if($null -eq $caption) {
        # Need to test this with the Windows 10 & 11 OS's
        $caption = Invoke-Command -ComputerName $MachineName -ScriptBlock { Get-ComputerInfo -Property WindowsProductName -ErrorAction SilentlyContinue } 
        if($null -eq $caption) {
            write-debug ("Get-ComputerInfo for machine {0} was null" -f $MachineName)
            $caption = (Get-WmiObject -ComputerName $MachineName -class Win32_OperatingSystem -ErrorAction SilentlyContinue)
            if($null -eq $caption) {
                Write-Error ("Unable to determine host {0}'s OS. Cannot proceed." -f $MachineName)
            }
            $caption.Caption
        }
        else {
            write-debug ("Get-ComputerInfo for machine {0} return {1}" -f $MachineName, $caption.WindowsProductName)
            $caption.WindowsProductName
        }
    }
    else {
        write-debug ("Get-ADComputer for machine {0} returned {1}" -f $MachineName, $caption.OperatingSystem)
        $caption.OperatingSystem
    }
}


$MachineTest = @'
    {
        "MachineName":"",
        "OS":"",
        "NeedsPatches":false,
        "InstallStatus":"Installed",
        "Keys": [
            {
                "Label": "Turn off Windows Defender Antivirus",
                "GPO": "Computer Configuration/Policies/Administrative Templates/Windows Components/Windows Defender Antivirus",
                "Path": "HKLM:\\Software\\Policies\\Microsoft\\Windows Defender",
                "Key": "DisableAntiSpyware",
                "Value": "",
                "Disabled": 1
            },
            {
                "Label": "Turn off Windows Defender Antivirus",
                "GPO": "Computer Configuration/Policies/Administrative Templates/Windows Components/Windows Defender Antivirus",
                "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "Key": "DpaDisabled",
                "Value": "",
                "Disabled": 1
            },
            {
                "Label": "Monitor file and program activity on your computer",
                "GPO": "Computer Configuration/Policies/Administrative Templates/Windows Components/Windows Defender Antivirus/Real-time Protection",
                "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "Key": "DisableOnAccessProtection",
                "Value": "",
                "Disabled": 1
            },
            {
                "Label":"Disable On Access Protection",
                "GPO": "Computer Configuration/Policies/Administrative Templates/Windows Components/Windows Defender Antivirus/Real-time Protection",
                "Path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 
                "Key": "DisableOnAccessProtection",
                "Value": "",
                "Disabled": 1
            },
            {
                "Label": "Disable Real Time Monitoring",
                "Path": "HKLM:\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "Key": "DisableRealtimeMonitoring",
                "Value": "",
                "Disabled": 1
            },
            {
                "Label": "Force Defender in Passive Mode",
                "Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection",
                "Key": "ForceDefenderPassiveMode",
                "Value": "",
                "Disabled": 1
            },
            {
                "Label": "Disable Real Time Monitoring",
                "Path": "HKLM:\\Software\\Microsoft\\Windows Defender\\Real-Time Protection",
                "Key": "DisableRealtimeMonitoring",
                "Value": "",
                "Disabled": 1
            },
            {
                "GPO": "Computer Configuration/Policies/Administrative Templates/Windows Components/Windows Defender Antivirus",
                "Label": "Turn off Windows Defender Antivirus",
                "Path": "HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                "Key": "DpaDisabled",
                "Value": "",
                "Disabled": 1
            },
            {
                "Label": "Disable Windows Defender AntiVirus",
                "Path":"HKLM:\\Software\\Microsoft\\Windows Defender",
                "Key":"DisableAntiVirus",
                "Value":"",
                "Disabled": 1
            }
        ]
    }
'@


$results = @()

#Iterate over the list of machines
$Machines | foreach {
    $machine = ConvertFrom-Json -InputObject $MachineTest
    $machine.MachineName = $_

    #$result = New-Object MachineDetails
    #$result.MachineName = $_
    $MachineName = $_

    #get the OS
    $version = Get-WindowsVersion $MachineName
    write-debug ("Machine {0} version string {1}" -f $MachineName, $version)
    #$result.OS = $version
    $machine.OS = $version

    $machine.Keys | foreach {
        $path = $_.Path
        $key = $_.Key
        $value = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath $path -RegKeyName $key
        if($null -eq $value) { $value = 0 }
        if($value -eq $_.Disabled) {
            $_.Value = "Yes"
        }
        else {
            $_.Value = "No"
        }

        Write-Host ("Test Machine {0} path '{1}:{2}' value {3}" -f $MachineName, $path, $key, $value)
    }

    #$antiSpyware = Get-DisableAntiSpywareSetting -MachineName $MachineName
    #write-debug ("Machine {0} antispyware disabled is {1}" -f $MachineName, $antiSpyware)
    #$result.AntiSpywareDisabled = $antiSpyware

    #$antiVirus = Get-DisableAntiVirusSetting -MachineName $MachineName
    #write-debug ("Machine {0} antivirus disabled is {1}" -f $MachineName, $antiVirus)
    #$result.AntiVirusDisabled = $antiVirus

    #$dpa = Get-DpaDisabled -MachineName $MachineName
    #write-debug ("Machine {0} DpaDisabled is {1}" -f $MachineName, $dpa)
    #$result.DpaDisabled = $dpa

    #$rtmDisabled = Get-DisableRealTimeMonitoring $MachineName
    #Write-Debug ("Machine {0} Real Time Monitoring Disabled is {1}" -f $MachineName, $rtmDisabled)
    #$result.RealTimeMonitoringDisabled = $rtmDisabled

    if($version -like "*Server*") {
        write-debug ("Machine {0} is a server. Performing Server MDE Checks" -f $MachineName)

        $installStatus = Get-ServerMdeInstalledStatus -MachineName $MachineName
        write-debug ("Machine {0} Defender Feature is {1}" -f $MachineName, $installStatus)
        if($installStatus -eq $true) {
            # $result.InstallStatus = "Installed"
            $machine.InstallStatus = "Installed"
        }
        else {
            # $result.InstallStatus = "Not Installed"
            $machine.InstallStatus = "Not Installed"
        }
        
        #$passiveMode = Get-ForcePassiveMode -MachineName $MachineName
        #write-debug ("Machine {0} force passive mode is {1}" -f $MachineName, $passiveMode)
        #$result.ForcePassiveMode = $passiveMode

        if($version -like "*Server 2012 R2*") {
            $machine.InstallStatus = "N/A"
            #run 2012 checks
            $updates = Get-Win2012R2Update -MachineName $MachineName
            if($null -eq $updates) {
                #$result.NeedsPatches = $true
                $machine.NeedsPatches = $true
            }
        }
        elseif($version -like "*Server 2016*") {
            #run 2016 checks
            $updates = Get-Win2016Update -MachineName $MachineName
            if($null -eq $updates) {
                # $result.NeedsPatches = $true
                $machine.NeedsPatches = $true
            }
        }
        #elseif($version -like "*Server 2019*") {
        #    #run 2019 Checks
        #}
    }

    #$results += $result
    $results += $machine
}

$results | Format-List -Property * -Expand Both