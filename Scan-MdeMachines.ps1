param (
    [Parameter(Mandatory)]
    [string[]]$ComputerNames
)

    $pendingRebootPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
    )

    $defenderProxyRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    $defenderProxyValues = @('ProxyMode', 'ProxyPacUrl', 'ProxyServer')

    $dataCollectionProxyRegPath = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection'
    $dataCollectionProxyValues = @('DisableEnterpriseAuthProxy', 'TelemetryProxyServer')

    $results = @{}

    foreach ($computer in $ComputerNames) {
        Write-Host "Checking $computer..."
        $pending = $false
        $defenderProxy = @{}
        $dataCollectionProxy = @{}

        # Usage inside Get-PendingRebootStatus:
        $pending = Test-PendingRebootRegistry -ComputerName $computer -RegistryPaths $pendingRebootPaths

        # Check Defender Proxy Registry Values
        if ($null -ne $pending) {
            $defenderProxy = Get-ProxySettings -ComputerName $computer -RegPath $defenderProxyRegPath -ValueNames $defenderProxyValues
            $dataCollectionProxy = Get-ProxySettings -ComputerName $computer -RegPath $dataCollectionProxyRegPath -ValueNames $dataCollectionProxyValues
        }

        results += [PSCustomObject]@{
            ComputerName    = $computer
            PendingReboot   = $pending
            DefenderProxy   = $defenderProxy
            DataCollectionProxy = $dataCollectionProxy
        }
    }

    Write-Host $results | Format-Table 

function Get-ProxySettings {
    param (
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [Parameter(Mandatory)]
        [string]$RegPath,
        [Parameter(Mandatory)]
        [string[]]$ValueNames
    )
    try {
        $proxyValues = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($regPath, $valueNames)
            $result = @{}
            if (Test-Path $regPath) {
                foreach ($name in $valueNames) {
                    $val = Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name -ErrorAction SilentlyContinue
                    $result[$name] = $val
                }
            }
            return $result
        } -ArgumentList $RegPath, $ValueNames -ErrorAction Stop

        return $proxyValues
    } catch {
        Write-Warning "Could not retrieve Defender proxy settings from $ComputerName: $_"
        return $null
    }
}

function Test-PendingRebootRegistry {
    param (
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [Parameter(Mandatory)]
        [string[]]$RegistryPaths
    )
    $pending = $false
    foreach ($path in $RegistryPaths) {
        try {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                param($regPath)
                if (Test-Path $regPath) {
                    return $true
                } else {
                    return $false
                }
            } -ArgumentList $path -ErrorAction Stop | ForEach-Object {
                if ($_ -eq $true) { $pending = $true }
            }
        } catch {
            Write-Warning "Could not connect to $ComputerName $_"
            $pending = $null
            break
        }
    }
    return $pending
}

