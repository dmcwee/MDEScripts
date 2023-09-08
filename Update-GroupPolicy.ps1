$machines = @("win2012r2","win2016","win2019")

$machines | foreach {
    Invoke-Command -ComputerName $_ -ScriptBlock { gpupdate.exe /force }
}