<#
=============================================================================

=============================================================================

#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory=$true, HelpMessage='List of machines to check for MDE readiness')]
    [string[]]$Machines,
    [Parameter(Mandatory=$true, HelpMessage='Acceptable output values: HTML, JSON, Screen')]
    [ValidateSet("HTML","JSON","Screen")]
    [string]$Output,
    [Parameter()]
    [string]$OutputFileName = "MDEReadinessResults"
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

function Get-RemoteHotFix {
    param(
        [string]$MachineName,
        [string[]]$Kbs
    )

    Write-Debug ("KB Count {0}" -f $Kbs.Count)
    try {
        $update = Get-HotFix -id $Kbs -ComputerName $MachineName
    }
    catch {
        write-debug ("Get-RemoteHotFix: Error caught calling Get-HotFix to remote machine {0}. Reverting to Invoke-Command." -f $MachineName)
        $update = Invoke-Command -ComputerName $MachineName -ScriptBlock { Get-HotFix -id $Using:Kbs }
    }
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

function Write-Html {
    param(
        $Results,
        $OutputFileName
    )

    $file = $OutputFileName + ".html"
    $Results | ConvertTo-Html | Out-File -FilePath $file
}

function Write-Json {
    param(
        $Results,
        $OutputFileName
    )

    $file = $OutputFileName + ".json"
    $Results | ConvertTo-Json | Out-File -FilePath $file
}

function Write-Screen {
    param(
        $Results
    )

    $Results | foreach {
        Write-Host ("Machine Name, OS, Needs Patches, Install Status")
        Write-Host ("{0}, {1}, {2}, {3}" -f $_.MachineName, $_.OS, $_.NeedsPatches, $_.InstallStatus)
        $_.GPOs | foreach {
            Write-Host ("     {0}({1}):{2}" -f $_.Label, $_.Key, $_.Value)
        }
        Write-Host "   "
    }
}

If ($PSBoundParameters[‘Debug’]) {
    $DebugPreference='Continue'
}

$results = @()
#$Kbs = (Get-Content "HotFixChecks.json" -Raw) | ConvertFrom-Json
$Tests = (Get-Content "Tests.json" -Raw) | ConvertFrom-Json

$machineTemplate = Get-Content "MachineResult.json" -Raw

$machineCount = 0
$machinePercent = 100 / $Machines.Count
$percentage = 0

#Iterate over the list of machines
$Machines | foreach {
    $step = 0
    $MachineName = $_

    $percentage = ($machinePercent * $machineCount) + ($machinePercent * $step)
    Write-Progress -Activity "Reviewing Machine $MachineName" -Status "Getting Machine Details" -PercentComplete $percentage
    
    $machine = $machineTemplate | ConvertFrom-Json
    $machine.MachineName = $_

    #get the OS
    $version = Get-WindowsVersion $MachineName
    write-debug ("Machine {0} version string {1}" -f $MachineName, $version)
    $machine.OS = $version

    $step = .33
    $percentage = ($machinePercent * $machineCount) + ($machinePercent * $step)
    Write-Progress -Activity "Reviewing Machine $MachineName" -Status "Checking GPOs that disable Defender" -PercentComplete $percentage

    $Tests.GPOs | foreach {
        $path = $_.Path
        $key = $_.Key
        $value = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath $path -RegKeyName $key

        if($null -eq $value) { 
            $value = "Not configured"
        }
        elseif($value -eq $_.Disabled) {
            $value = "Disabled"
        }
        else {
            $value = "Enabled"
        }

        Write-Debug ("Test Machine {0} path '{1}:{2}' value {3}" -f $MachineName, $path, $key, $value)
        $gpo = $_
        $gpo.Value = $value
        $machine.GPOs += $gpo
    }

    $step = .66
    $percentage = ($machinePercent * $machineCount) + ($machinePercent * $step)
    Write-Progress -Activity "Reviewing Machine $MachineName" -Status "Checking for missing updates (KBs)" -PercentComplete $percentage
    if($version -like "*Server*") {
        write-debug ("Machine {0} is a server. Performing Server MDE Checks" -f $MachineName)

        $installStatus = Get-ServerMdeInstalledStatus -MachineName $MachineName
        write-debug ("Machine {0} Defender Feature is {1}" -f $MachineName, $installStatus)
        if($installStatus -eq $true) {
            $machine.InstallStatus = "Installed"
        }
        else {
            $machine.InstallStatus = "Not Installed"
        }
        
        if($version -like "*Server 2012 R2*") {
            $machine.InstallStatus = "N/A"

            #Get 2012 HotFixIds
            $HotFixIds = $Tests.Kbs | Where-Object -Property OS -eq "Win2012R2" | Select-Object -ExpandProperty HotFixId
        }
        elseif($version -like "*Server 2016*") {
            #Get 2016 HotFixIds
            $HotFixIds = $Tests.Kbs | Where-Object -Property OS -eq "Win2016" | Select-Object -ExpandProperty HotFixId
        }
        elseif($version -like "*Server 2019*") {
            #Get 2019 HotFixIds - None used in 09/2023 but this may change in the future
            $HotFixIds = $Tests.Kbs | Where-Object -Property OS -eq "Win2019" | Select-Object -ExpandProperty HotFixId
        }

        Write-Debug ("Machine {0} HotFix Count: {1}" -f $MachineName, $HotFixIds.Count)
        if($HotFixIds.Count -gt 0) {
            $updates = Get-RemoteHotFix -MachineName $MachineName -Kbs $HotFixIds
            if($null -eq $updates) {
                $machine.NeedsPatches = $true
            }
            else {
                $machine.NeedsPatches = $false
            }
        }
        else {
            $machine.NeedsPatches = $false
        }
        
    }

    $results += $machine
    $machineCount += 1
}

if($Output -eq "JSON") {
    Write-Json -Results $results -OutputFileName $OutputFileName
}
elseif($Output -eq "HTML") {
    Write-Html -Results $results -OutputFileName $OutputFileName
}
elseif($Output -eq "Screen") {
    Write-Screen -Results $results
}

