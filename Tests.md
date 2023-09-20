# Tests

The tests file contains all of the tests for the various phases of the MDE assessment.

## KBs

This is the list of KBs that need to be installed on the machine in order to support onboarding. For Windows Server 2012 R2 and Windows Server 2016 these KBs are needed prior to deploying the Defender for Down Level Servers Unified Agent.

## GPO Checks

GPO Checks are preformed to detect what GPOs may be in place that prevent Defender from activating properly during it's onboarding phase. While not all of these must be changed to onboard they all have an impact on how Defender will perform.

### DisplayValues

The GPO DisplayValues array is used to align the output with the GPO User Interface. Because the script returns the value -1 to indicate that a GPO setting was *Not Configured* the indexing of the array is: Value + 1.
