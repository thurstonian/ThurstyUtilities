# Copies exhibit stamps file from network share to stamps folder for user.
# Works remotely
function Add-ExhibitStamps {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[String]$ComputerName,
		[Parameter(Mandatory)]
		[String]$UserName
	)
	Copy-Item -Path "\\cozen\deploy\source\Adobe\Pro DC\Exhibit Stamp\Exhibit-Stamp.pdf" -Destination "\\$ComputerName\c$\Users\$UserName\AppData\Roaming\Adobe\Acrobat\DC\Stamps"
}

# Helper function to connect to Exchange Online Powershell using currently signed on user
function Connect-EXO {
	$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -Split "\\"
	Connect-ExchangeOnline -UserPrincipalName ("" + $Identity[1] + "@" + $Identity[0] + ".com") -ShowBanner:$false
}

# The new LAPS command is slow and sucks. Let's fix that.
function Get-LAPSAzurePassword {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[String]$ComputerName
	)
	Test-MgGraph
	Connect-MgGraph -Scopes "Device.Read.All", "DeviceLocalCredential.Read.All" -NoWelcome
	Get-LapsAADPassword -DeviceIds (Get-MgDevice -Filter "DisplayName eq '$ComputerName'").DeviceId -IncludePasswords -AsPlainText
	(Disconnect-MgGraph) > nul
}

# Installs the latest version of Winget onto the current computer
function Install-WinGet {
	If ($null -ne (Get-Command "winget" -ErrorAction SilentlyContinue)) {
		Write-Host "Winget is already installed."
		Return
	}
	$WingetUrl = "https://github.com/microsoft/winget-cli/releases/"
	If ($null -eq (Get-AppxPackage "Microsoft.UI.Xaml.2.8*" -AllUsers)) {
		Write-Host "Downloading Microsoft UI XAML..."
		Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml" -OutFile ($env:TEMP + "xaml.zip")
		Expand-Archive -LiteralPath ($AdminPath + "xaml.zip") -DestinationPath ($env:TEMP + "xaml")
		Add-AppxPackage ($env:TEMP + "xaml\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.8.appx") -AllUsers
	}
	$WingetVersion = [System.Net.WebRequest]::Create($WingetUrl + "latest").GetResponse().ResponseUri.OriginalString.split('/')[-1].Trim('v')
	Invoke-WebRequest -Uri ($WingetUrl + "download/v" + $WingetVersion + "/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle") -OutFile ($env:TEMP + "winget.msixbundle")
	Add-AppxPackage ($env:TEMP + "winget.msixbundle")
}

# Generates a new tap for a user account given an email address
function New-TAP {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$Email
	)

	$reqBody = @{
		startDateTime     = Get-Date
		lifetimeInMinutes = 480
		isUsableOnce      = $false
	}

	Test-MgGraph
	Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All" -NoWelcome
	Write-Host (New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $Email -BodyParameter ($reqBody | ConvertTo-Json)).TemporaryAccessPass
	(Disconnect-MgGraph) >nul
}

# Removes the Bad iManage Adobe Reader addin from a remote computer
function Remove-ReaderAddin {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[String]$ComputerName
	)
	$AddinPath = "\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\plug_ins\IManAcrobatReader10.api"

	Test-ElevatedPrivileges

	# Check for Adobe Reader on local machine

	$ReaderInstalled = $false

	Write-Host "Fetching remote registry keys..."
	$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName) # Gets remote HKLM Base Key

	If ($null -ne $BaseKey) { Write-Host "Success!" }

	Write-Host "Searching 32Bit Programs..."
	$32BitKeys = $BaseKey.OpenSubKey("Software\wow6432node\microsoft\Windows\Currentversion\uninstall")
	ForEach ($Key in $32BitKeys.GetSubKeyNames()) {
		$SubKey = $32BitKeys.OpenSubKey($Key)
		If ($SubKey.GetValue("DisplayName") -like "*Reader*") { 
			Write-Host "Adobe Reader Located!"
			$ReaderInstalled = $true
			$SubKey.Close()
			Break
		}
		$SubKey.Close()
	}
	$32BitKeys.Close()

	If (-not $ReaderInstalled) {
		Write-Host "Searching 64Bit Programs..."
		$64BitKeys = $BaseKey.OpenSubKey("Software\microsoft\Windows\Currentversion\uninstall")
		ForEach ($Key in $64BitKeys.GetSubKeyNames()) {
			$SubKey = $64BitKeys.OpenSubKey($Key)
			If ($SubKey.GetValue("DisplayName") -like "*Reader*") {
				Write-Host "Adobe Reader Located!"
				$ReaderInstalled = $true
				$SubKey.Close()
				Break
			}
			$SubKey.Close()
		}
		$64BitKeys.Close()
	}

	$BaseKey.Close()

	If ($ReaderInstalled -and (Test-Path ("\\" + $ComputerName + "\c$" + $AddinPath))) {
		Write-Host "Attempting to remove the Reader addin from the $ComputerName..."
		While ((Test-Path ("\\" + $ComputerName + "\c$" + $AddinPath))) {
			Remove-Item -Force ("\\" + $ComputerName + "\c$" + $AddinPath)
		}
	}

	If (-not (Test-Path ("\\" + $ComputerName + "\c$" + $AddinPath))) {
		Write-Host "Reader addin successfully removed!"
	}
}

# Removes Windows Hello pin from the current computer
# Doesn't work right now despite testing
# God help your soul if you try to fix it
function Remove-WindowsHelloPin {
	Test-ElevatedPrivileges
	takeown /f "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" /r /d y >nul
	icacls "C:\WINDOWS\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" /reset /t /c /l /q
	Remove-Item -Path "C:\WINDOWS\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" -Recurse -Force
}

# Restarts Onelog on the current computer
function Restart-OneLog {
	$Path = "\ITS\OneLog\Client\LoginApplication.exe"
	$Service = Get-Service -Name "ITS Onelog Client"
	If ($Service.Status -eq "Running") {
		Restart-Service -InputObject $Service -Force
	} Else {
		Start-Service -InputObject $Service
	}
	Get-Process -Name LoginApplication | Stop-Process
	If (Test-Path -Path "$ENV:ProgramFiles$Path") {
		& "$ENV:ProgramFiles$Path"
	} ElseIf (Test-Path -Path "${ENV:ProgramFiles(x86)}$Path") {
		& "${ENV:ProgramFiles(x86)}$Path"
	}
}

# Stops all umbrella services on the current computer
function Stop-Umbrella {
	Test-ElevatedPrivileges
	Get-Service -Name "*umbrellaagent*" | Where-Object { $_.Status -eq "Running" } | Stop-Service
	Get-Service -Name "*swgagent*" | Where-Object { $_.Status -eq "Running" } | Stop-Service
}

# Checks AD for users who have Adobe Licenses
function Test-AdobeLicense {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]	
		[String]$SearchFor
	)
    (Get-ADGroup -Identity "Adobe Pro Licensed Users" -Properties Member).Member | Select-String -Pattern $SearchFor
}

# Checks if the current session is running as Admin
function Test-ElevatedPrivileges {
	[CmdletBinding()]
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal $identity
	If (-Not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		throw "Not running with elevated privileges"
	}
}

# Checks if Exchange Online Powershell is currently connected
function Test-EXOConnection {
	If ($null -ne (Get-ConnectionInformation)) {
		Write-Error "Exchange Online already connected. Disconnecting..."
		Disconnect-ExchangeOnline -Confirm:$false
	}
}

# Checks if an email address is on Exchange Online or not
function Test-EXOMoved {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$Email
	)
	Test-EXOConnection
	Connect-EXO
	$Mailbox = Get-EXOMailbox -Identity $Email 2>nul
	Disconnect-ExchangeOnline -Confirm:$false
	
	If ($Mailbox) {
		Write-Host "$Email is on Exchange Online"
	} Else {
		Write-Host "$Email is NOT on Exchange Online"
	}
}

# Checks if Microsoft Graph is connected
function Test-MgGraph {
	If ($null -ne (Get-MgContext)) {
		Write-Error "Microsoft Graph already connected. Disconnecting..."
		Disconnect-MgGraph >nul
	}
}