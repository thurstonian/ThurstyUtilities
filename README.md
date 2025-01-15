# ThurstyUtilities

If you've found this, you're likely one of my coworkers. Hi! I wrote this because we do a lot of stuff that's very repetetive, and a lot of stuff that's overly complicated for how simple the result is, and I wanted to make it easier on us.

## Prerequisites

- Powershell 7
- Microsoft Graph Module
- Exchange Online Module
- ffmpeg (Optional)

To update to the newest version of PowerShell, run the following command in an Admin-Elevated PowerShell window:

`winget install Microsoft.PowerShell --scope machine`

Then, to install the required modules, you'll need to run the following:

`Install-Module Microsoft.Graph`

`Install-Module ExchangeOnlineManagement`

You can get the currently imported modules with `Get-Module`, and if you don't see Microsoft Graph or Exchange Online, you can just run these commands:

`Import-Module Microsoft.Graph`

`Import-Module ExchangeOnlineManagement`

If you'd like to run the cmdlets for editing video, install ffmpeg using the following command in an Admin-Elevated PowerShell window:

`winget install Gyan.FFmpeg --scope machine`

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

### Connect-MSGraph

Helper function to connect to Microsoft Graph.

First tests for already saved access token in the root user folder and uses that, specifically ~/graphToken (which should be stored as a plaintext file (I know this isn't security best practice but shhh it's only temporary I'll set it up to allow reading from a secure string at some point)).

If no access token is detected, it will then check for any scopes passed in, then prompt to connect in the web browser using Microsoft's regular Auth flow.
Parameters:
- Scopes (Optional)

### Get-LAPSAzurePassword

Gets the currently active LAPS password for a given computer.

Parameters:
- ComputerName (Required)

MS Graph Scopes:
- Device.Read.All (To convert Computer Names into DeviceIDs)
- DeviceLocalCredential.Read.All (To read plaintext LAPS Passwords)

### Get-PasswordExpiration

Fetches the password expiration date and time of any domain user account across the whole forest.

Parameters:
- Domain (Optional, Defaults to cozen.com)
- UserName (Required)

### Install-WinGet

Installs the WinGet Package Manager if it's not installed already.

### New-TAP

Generates a new Temporary Access Pass for a given user. Valid for 8 hours.

Parameters:
- Email (Required)

MS Graph Scopes:
- UserAuthenticationMethod.ReadWrite.All (To create new TAP for user)

### Remove-ReaderAddin

Removes the corrupt Adobe Reader addin (IManAcrobatReader10.api) from a remote computer.

Parameters:
- ComputerName (Required)

### Remove-WindowsHelloPin

**CURRENTLY NOT WORKING, USE AT YOUR OWN RISK**

Attempts to remove Windows Hello pins from the local computer.

### Restart-OneLog

Restarts the ITS OneLog client on the local computer.

### Resize-Video

Wrapper function for ffmpeg, will throw an error if not installed.

Trims a given video file from the given start time to a provided ending time.

If using the TrimSeconds parameter instead of EndTime, an EndTime is calculated by subtracting the amount of seconds given from the length of the video.

Parameters:
- StartTime (Optional, defaults to beginning of video)
- EndTime (Required if not using TrimSeconds)
- TrimSeconds [Integer] (Optional, defaults to 0)
- InputPathString (Required)
- OutputPathString (Required)

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
