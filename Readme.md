# MDE Scripts

Please note these scripts are still being worked and improved. The best output is currently to JSON or to the screen but HTML is coming soon.

## Get-MdeMigrationReadyState

This script is intended to scan the list of machines provided to check for some common pre-migration needs.

1. Verify Defender Features are Installed (Windows Server 2016+)
1. Verify KBs are Installed (Windows Server 2012 R2+)
1. Check for GPO settings that inhibit various Defender features from acting normally

### Requirements

1. Windows PowerShell Remote Calls to targeted endpoints
1. Locate the Test.json and file in the same folder as the Get-MdeMigrationReadyState.ps1 script
1. Locate the MachineResult.json file in the

### Recommendation

1. Run this from a machine that has Active Directory PowerShell Module installed
1. Run this as a user who can execute Active Directory PowerShell calls (Get-ADComputer)

### Running Script

```
PS> Get-MdeMigrationReadyState.ps1 -Machines FirstServer, SecondServer, ThirdServer -Output Screen
```

**or**
```

PS> Get-MdeMigrationReadyState.ps1 -Machines FirstServer, SecondServer, ThirdServer -Output JSON -OutputFileName SeptReadinessResult
```

The script takes 3 parameters:

1. **Machines:** A list of machines (Windows Servers) to check for migration readiness
1. **Output:** JSON, Screen, or HTML are valid values. JSON & HTML will create a local file with the output while screen will print a summary. Currently it is best to use JSON or Screen as HTML is a work in progress
1. **OutputFileName:** *(Default: MDEReadinessResults) The file where results should be written. A `.json` or `.html` file extensions will be appended to the value provided here.

### Limitations

#### Servers Only

The script has been tested with Windows Server 2012 R2, 2016, and 2019. The script is expected to work for any OS that is Windows Server 2012 R2 or newer.

Client testing is occuring but not complete, and testing against a client may require changes to client machines or Domain GPOs in order to allow the remote powershell execution.

#### Active Directory Module & Remoting

The script tries to use Get-ADComputer from the AD PowerShell Module. If this fails, or if other remote calls fail the script will attempt to 'fall back' to other remoting calling methods until remote call attempts are exhausted.

## Update-GroupPolicy

Convenience script that performs a remote GPUpdate on the machines provided on the command line.

### Running Script

```
PS> Update-GroupPolicy.ps1 -Machines FirstServer, SecondServer, ThirdServer
```