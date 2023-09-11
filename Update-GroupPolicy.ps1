param(
    [Parameter(Mandatory=$true, HelpMessage='List of machines to check for MDE readiness')]
    [string[]]$Machines = @("win2012r2,win2016,win2019")
)

$Machines | foreach {
    Invoke-Command -ComputerName $_ -ScriptBlock { gpupdate.exe /force }
}