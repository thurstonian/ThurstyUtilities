# ThurstyUtilities

If you've found this, you're likely one of my coworkers. Hi! I wrote this because we do a lot of stuff that's very repetetive, and a lot of stuff that's overly complicated for how simple the result is, and I wanted to make it easier on us.

## Prerequisites

Right now, there's only 3 things this module requires: An updated version of PowerShell, and two Microsoft modules that run as dependencies.

To update to the newest version of PowerShell, run the following command in an Admin-Elevated PowerShell window:

`winget install Microsoft.PowerShell --scope machine`

Then, to install the required modules, you'll need to run the following:

`Install-Module Microsoft.Grpah`
`Install-Module ExchangeOnlineManagement`

You can get the currently imported modules with `Get-Module`, and if you don't see Microsoft Graph or Exchange Online, you can just run these commands:

`Import-Module Microsoft.Grpah`
`Import-Module ExchangeOnlineManagement`

That should leave you all set with the most up to date version of PowerShell and the necessary modules to run this one!

## Installing

I try to keep an up-to-date copy of the module on our servers, so installing the module should be as easy as importing directly from the server.

`Import-Module \\cozen\phq\shared\sthurston\ThurstyUtilities`

For the more advanced, you can always clone the repository locally and import from there. Or clone directly into your PowerShell Modules directory and implicity import.

## List of cmdlets

Below is a list of cmdlets, their parameters, and a brief description of what they do.

### Add-ExhibitStamps

Remotely installs Exhibit Stamps for a user's Adobe Acrobat.

Parameters:
	- ComputerName (Required)
	- UserName (Required)

### Connect-EXO

Connects to the Exchange Online tenant with the currently signed in user.

### Install-WinGet

Installs the WinGet Package Manager if it's not installed already.

### New-TAP

Generates a new Temporary Access Pass for a given user. Valid for 8 hours.

Parameters:
	- Email (Required)

### Remove-ReaderAddin

Removes the corrupt Adobe Reader addin (IManAcrobatReader10.api) from a remote computer.

Parameters:
	- ComputerName (Required)

### Remove-WindowsHelloPin

Attempts to remove Windows Hello pins from the local computer.

### Set-LAPSPassword

Gets the currently active LAPS password for a given computer.

Parameters:
	- ComputerName (Required)

### Stop-Umbrella

Stops all running instances of Cisco Umbrella on the current computer.

### Test-AdobeLicense

Checks in Active Directory to see if a user has been assigned with an Adobe License. Does a pattern match over the Distringuihed Name, so you can search by first name, last name, domain, or organizational unit.

Parameters:
	- SearchFor (Required)

### Test-ElevatedPrivileges

Checks if the currently running PowerShell window is running with elevated privilages (as admin).

### Test-EXOConnection

Checks if there is an active Exchange Online connection, and closes it if there is.

### Test-EXOMoved

Checks Exchange Online to see if a users mailbox has been migrated.

Parameters:
	- Email (Required)

### Test-MgGraph

Checks for Microsoft Graph connections, and closes any that are open.
