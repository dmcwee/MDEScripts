param(
    [string[]]$Machines
)

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

    Get-WindowsFeature | Where -Property Name -like "*efender*"
}

function Get-DisableAntiSpywareSetting {
    param (
        [string]$MachineName
    )

    #look at HybridModeEnabled as well to determine what it means

    $p = $p = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows Defender' -Name DisableAntiSpyware
    $p.DisableAntiSpyware
}

function Get-DisableAntiSpywareSetting {
    param (
        [string]$MachineName
    )

    $p = $p = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows Defender' -Name DisableAntiVirus
    $p.DisableAntiVirus
}

function Get-ForcePassiveMode {
    param (
        [string]$MachineName
    )

    $p = $p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' -Name ForceDefenderPassiveMode
    $p.ForceDefenderPassiveMode
}

function Get-Win2012R2Update {
    param (
        [string]$MachineName
    )

    $update = Get-HotFix -id "KB3045999" -ComputerName $MachineName
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

    $update = Get-HotFix -id $SSUKbs -ComputerName $MachineName
    $update
}

Get-WindowsVersion {
    param(
        [string]$MachineName
    )

    # Need to test this with the Windows 10 & 11 OS's
    $caption = Invoke-Command -ComputerName $MachineName -ScriptBlock { Get-ComputerInfo -Property WindowsProductName } -ErrorSilently
    if($null -eq $caption) {
        $caption = (Get-WmiObject -ComputerName $MachineName -class Win32_OperatingSystem ).Caption -ErrorSilently
        if($null -eq $caption) {
            Write-Error ("Unable to determine host {0}'s OS. Cannot proceed." -f $MachineName)
        }
    }

    # WMI Object will return a value like:
    # "Microsoft Windows Server 2012 R2 Datacenter"
    # "Microsoft Windows Server 2019 Datacenter"

    # Get-ComputerInfo will return a value like:
    # "Windows Server 2019 Datacenter"
    # "Windows Server 2016 Datacenter"
}

#Iterate over the list of machines
$Machines | foreach {
    #get the OS
    $version = Get-WindowsVersion $_

    if($version -like "*Server 2012 R2*") {
        #run 2012 checks
    }
    else if($version -like "*Server 2016*") {
        #run 2016 checks
    }
    else if($version -like "*Server 2019*") {
        #run 2019 Checks
    }
}