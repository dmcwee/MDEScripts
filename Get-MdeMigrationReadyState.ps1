<#
=================================================================================================================
 _____      _         ___  ___    _     ___  ____                 _   _            ______               _       
|  __ \    | |        |  \/  |   | |    |  \/  (_)               | | (_)           | ___ \             | |      
| |  \/ ___| |_ ______| .  . | __| | ___| .  . |_  __ _ _ __ __ _| |_ _  ___  _ __ | |_/ /___  __ _  __| |_   _ 
| | __ / _ \ __|______| |\/| |/ _' |/ _ \ |\/| | |/ _' | '__/ _' | __| |/ _ \| '_ \|    // _ \/ _' |/ _' | | | |
| |_\ \  __/ |_       | |  | | (_| |  __/ |  | | | (_| | | | (_| | |_| | (_) | | | | |\ \  __/ (_| | (_| | |_| |
 \____/\___|\__|      \_|  |_/\__,_|\___\_|  |_/_|\__, |_|  \__,_|\__|_|\___/|_| |_\_| \_\___|\__,_|\__,_|\__, |
                                                   __/ |                                                   __/ |
                                                  |___/                                                   |___/
==================================================================================================================
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory=$true, HelpMessage='List of machines to check for MDE readiness')]
    [string[]]$Machines,
    [Parameter(Mandatory=$true, HelpMessage='Acceptable output values: HTML, JSON, CSV, Screen')]
    [ValidateSet("HTML","JSON","Screen","CSV")]
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

    $feature = Get-WindowsOptionalFeature -Online | Where -Property FeatureName -like "*efender*"
    Write-Debug ("Machine {0} feature: {1}" -f $MachineName, $feature)
    $feature
}

function Get-ServerMdeInstalledStatus {
    param (
        [string]$MachineName
    )

    $installed = (Get-WindowsFeature -Name Windows-Defender -ComputerName $MachineName).Installed
    Write-Debug ("Machine {0} install status: {1}" -f $MachineName, $installed)
    $installed
}

function Get-RemoteRegistryValue {
    param(
        [string]$MachineName,
        [string]$RegKeyPath,
        [string]$RegKeyName
    )

    $r = Invoke-Command -ComputerName $MachineName -ScriptBlock { Get-ItemProperty -Path $Using:RegKeyPath -Name $Using:RegKeyName -ErrorAction SilentlyContinue }
    Write-Debug ("Machine {0} RegItem '{1}:{2}' value {3}" -f $MachineName, $RegKeyPath, $RegKeyName, $r.$RegKeyName)
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

function Get-RemoteCertificates {
    param(
        [string]$MachineName,
        [string]$Thumbprint
    )

    Write-Debug ("Get-RemoteCertificates")
    try {
        $cert = Invoke-Command -ComputerName $MachineName -ScriptBlock { Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object -Property Thumbprint -EQ $Using:Thumbprint }
    }
    catch {
        Write-Error ("Get-RemoteCertificates: Error caught calling Get-ChildItem in ScriptBlock of Invoke-Command on {0}. Sending back null." -f $MachineName)
    }
    $cert
}

function Get-MissingRemoteValues {
    param (
        [string]$MachineName,
        [string]$RegKeyPath,
        [string]$RegKeyName,
        [string[]]$Values
    )

    $multiValue = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath $RegKeyPath -RegKeyName $RegKeyName
    $missingValues = @()
    $Values | ForEach-Object {
        if(!$multiValue.Contains($_)) {
            $missingValues += $_
        }
    }

    $missingValues
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

function Get-Tests {
    $testsText = Get-Content "Tests.json" -Raw -ErrorAction SilentlyContinue
    if($null -eq $testsText) {
        Write-Debug "Tests.json doesn't exist. Attempting to retrieve from Github."
        $testsText = (curl "https://raw.githubusercontent.com/dmcwee/MDEScripts/master/Tests.json").Content
    }

    Write-Debug "TestsText = $testsText"
    $tests = $testsText | ConvertFrom-Json
    $tests
}

function Get-MachineTemplate {
    $machineTemplate = Get-Content "MachineResult.json" -Raw -ErrorAction SilentlyContinue
    if($null -eq $machineTemplate) {
        Write-Debug "MachineResult.json doesn't exist. Attempting to retrieve from Github."
        $machineTemplate = (curl "https://raw.githubusercontent.com/dmcwee/MDEScripts/master/MachineResult.json").Content
    }

    $machineTemplate
}

function Write-CSV {
    param(
        $Results,
        $outputFileName
    )

    #Need to flatten the object so the CSV can display the GPO fields properly
    $Results | ForEach-Object {
        $result = $_
        $_.GPOs | ForEach-Object {
            $result | Add-Member -MemberType NoteProperty -Name $_.Key -Value $_.DisplayValues[$_.Value + 1]
        }
    }

    $file = $outputFileName + ".csv"
    $Results | Export-Csv -Path $file -NoTypeInformation
}

function Write-Html {
    param(
        $Results,
        $OutputFileName
    )

    $htmlTemplate = Get-Content "ResultsOutputTemplate.html" -Raw -ErrorAction SilentlyContinue
    if($null -eq $htmlTemplate){
        Write-Debug "ResultsOutputTemplate.html doesn't exist. Attempting to retrieve from Github"
        $htmlTemplate = (curl "https://raw.githubusercontent.com/dmcwee/MDEScripts/master/ResultsOutputTemplate.html").Content
    }

    $output = $htmlTemplate.Replace("{0}", (ConvertTo-Json $Results -Depth 4))

    $file = $OutputFileName + ".html"
    $output | Out-File -FilePath $file
}

function Write-Json {
    param(
        $Results,
        $OutputFileName
    )

    $file = $OutputFileName + ".json"
    $Results | ConvertTo-Json -Depth 4 | Out-File -FilePath $file
}

function Write-Screen {
    param(
        $Results
    )

    $Results | ForEach-Object {
        Write-Host ("Machine Name, OS, Needs Patches, Install Status")
        Write-Host ("{0}, {1}, {2}, {3}" -f $_.MachineName, $_.OS, $_.NeedsPatches, $_.InstallStatus)
        Write-Host ("  -- GPO Checks --")
        $_.GPOs | ForEach-Object {
            $value = $_.Value + 1
            Write-Host ("     {0}({1}): {2}({3})" -f $_.Label, $_.Key, $_.DisplayValues[$value], $_.Value)
        }
        Write-Host (" -- Root Cert Checks --")
        $_.Certificates | ForEach-Object {
            Write-Host ("     Missing: {0} Available to Download {1}" -f $_.Name, $_.Link) 
        }
        Write-Host ("  -- Cypher Function Checks --")
        $_.MissingCypherFunctions | ForEach-Object {
            Write-Host ("     Missing {0} from HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002\Functions" -f $_)
        }
        Write-Host "   "
    }
}

function Write-Banner {
    Write-Output(
"=================================================================================================================
 _____      _         ___  ___    _     ___  ____                 _   _            ______               _       
|  __ \    | |        |  \/  |   | |    |  \/  (_)               | | (_)           | ___ \             | |      
| |  \/ ___| |_ ______| .  . | __| | ___| .  . |_  __ _ _ __ __ _| |_ _  ___  _ __ | |_/ /___  __ _  __| |_   _ 
| | __ / _ \ __|______| |\/| |/ _' |/ _ \ |\/| | |/ _' | '__/ _' | __| |/ _ \| '_ \|    // _ \/ _' |/ _' | | | |
| |_\ \  __/ |_       | |  | | (_| |  __/ |  | | | (_| | | | (_| | |_| | (_) | | | | |\ \  __/ (_| | (_| | |_| |
 \____/\___|\__|      \_|  |_/\__,_|\___\_|  |_/_|\__, |_|  \__,_|\__|_|\___/|_| |_\_| \_\___|\__,_|\__,_|\__, |
                                                   __/ |                                                   __/ |
                                                  |___/                                                   |___/
==================================================================================================================")
}

If ($PSBoundParameters['Debug']) {
    $DebugPreference='Continue'
}

$results = @()
$Tests = Get-Tests

$machineTemplate = Get-MachineTemplate

$machineCount = 0
$machinePercent = 100 / $Machines.Count
$percentage = 0

#Iterate over the list of machines
$Machines | ForEach-Object {
    $step = 0
    $MachineName = $_

    $percentage = ($machinePercent * $machineCount) + ($machinePercent * $step)
    Write-Progress -Activity "Reviewing Machine $MachineName" -Status "Getting Machine Details" -PercentComplete $percentage
    
    $machine = $machineTemplate | ConvertFrom-Json
    $machine.MachineName = $_

    #get the OS
    $version = Get-WindowsVersion $MachineName
    $machine.OS = $version

    $step = .2
    $percentage = ($machinePercent * $machineCount) + ($machinePercent * $step)
    Write-Progress -Activity "Reviewing Machine $MachineName" -Status "Checking GPOs that disable Defender" -PercentComplete $percentage
    $Tests.GPOs | ForEach-Object {
        $path = $_.Path
        $key = $_.Key
        $value = Get-RemoteRegistryValue -MachineName $MachineName -RegKeyPath $path -RegKeyName $key

        if($null -eq $value) { 
            $value = -1
        }

        $gpo = $_
        $gpo.Value = [int]$value
        $machine.GPOs += $gpo
    }

    $step = .4
    $percentage = ($machinePercent * $machineCount) + ($machinePercent * $step)
    Write-Progress -Activity "Reviewing Machine $MachineName" -Status "Checking GPOs that disable Defender" -PercentComplete $percentage
    $Tests.Certificates | ForEach-Object {
        $thumbprint = $_.Thumbprint
        $value = Get-RemoteCertificates -MachineName $MachineName -Thumbprint $thumbprint

        if($null -eq $value) {
            $machine.Certificates += $_
        }
    }

    $step = .6
    $percentage = ($machinePercent * $machineCount) + ($machinePercent * $step)
    Write-Progress -Activity "Reviewing Machine $MachineName" -Status "Checking GPOs that disable Defender" -PercentComplete $percentage
    $Tests.CrypherChecks | ForEach-Object {
        $path = $_.Path
        $key = $_.Key
        $values = $_.values

        $missing = Get-MissingRemoteValues -MachineName $MachineName -RegKeyPath $path -RegKeyName $key -Values $values
        $machine.MissingCypherFunctions = $missing
    }

    $step = .8
    $percentage = ($machinePercent * $machineCount) + ($machinePercent * $step)
    Write-Progress -Activity "Reviewing Machine $MachineName" -Status "Checking for missing updates (KBs)" -PercentComplete $percentage
    if($version -like "*Server*") {
        Write-Debug ("Machine {0} is a server. Performing Server MDE Checks" -f $MachineName)

        $installStatus = Get-ServerMdeInstalledStatus -MachineName $MachineName
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
elseif($Output -eq "CSV") {
    Write-CSV -Results $results -outputFileName $OutputFileName
}
else {
    Write-Screen -Results $results
}