# Copies exhibit stamps file from network share to stamps folder for user.
# Works remotely
function Add-ExhibitStamp {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$ComputerName,
		[Parameter(Mandatory)]
		[String]$UserName
	)
	Invoke-WebRequest -Uri "https://www.utd.uscourts.gov/sites/utd/files/Exhibit-Stamp.pdf" -OutFile "\\$ComputerName\c$\Users\$UserName\AppData\Roaming\Adobe\Acrobat\DC\Stamps"
}

# Helper function to connect to Exchange Online Powershell using currently signed on user
function Connect-EXO {
	Test-EXOConnection
	$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\"
	Connect-ExchangeOnline -UserPrincipalName ("" + $Identity[1] + "@" + $Identity[0] + ".com") -ShowBanner:$false
}

# Helper function to connect to Microsoft Graph. Tests for already saved access token in the root user folder and uses that.
function Connect-MSGraph {
	[CmdletBinding()]
	param (
		[Parameter()]
		[String[]]$Scopes
	)

	# Test for existing MgGraph connection, disconnect if extant
	Test-MgGraph

	if (Test-Path -Path "~\graphToken") {
		Connect-MgGraph -AccessToken (Get-Content ~\graphToken | ConvertTo-SecureString -AsPlainText -Force) -NoWelcome
	} else {
		if ($null -ne $Scopes) {
			Connect-MgGraph -Scopes $Scopes -NoWelcome
		} else {
			Connect-MgGraph -NoWelcome
		}
	}
}

# Gets members of a distribution list and translates to ms graph user objects.
function Get-DistroMembers {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$Group
	)
	Connect-EXO
	Connect-MSGraph -Scopes @("User.Read.All")
	(Get-DistributionGroupMember -Identity $Group).Name | ForEach-Object {
		if (Test-UUID $_.Name) {
			Get-MgUser -UserId $_.Name
		} else {
			$ShortName = $_.Name.Substring(0,($_.Name.Length - 3))
			Get-MgUser -Filter "startswith(DisplayName, '$ShortName')"
		}
	}
}

# The new LAPS command is slow and sucks. Let's fix that.
function Get-LapsAzurePassword {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$ComputerName
	)
	Connect-MSGraph -Scopes @("Device.Read.All", "DeviceLocalCredential.Read.All")
	Get-LapsAADPassword -DeviceIds (Get-MgDevice -Filter "DisplayName eq '$ComputerName'").DeviceId -IncludePasswords -AsPlainText
	(Disconnect-MgGraph) > nul
}

# Get the password expiration for any user on any domain
function Get-PasswordExpiration {
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateSet("cozen.com","nationalsubrogation.com","mha.com","connectbridge.com", IgnoreCase = $true)]
		[String]$Domain = "cozen.com",
		[Parameter(Mandatory)]
		[String]$UserName
	)

	$Server = (Get-ADDomainController -DomainName $Domain -Discover -NextClosestSite).HostName
	try {
		Get-ADUser -Server "$Server" -Identity $UserName -Properties DisplayName, msDS-UserPasswordExpiryTimeComputed |
		Select-Object -Property Displayname,@{Name = "Expiration Date";Expression = { [datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed") } }
	} catch {
		throw "User is not in domain $Domain!"
	}
}

# Installs the latest version of Winget onto the current computer
function Install-WinGet {
	if ($null -ne (Get-Command "winget" -ErrorAction SilentlyContinue)) {
		Write-Error "Winget is already installed."
		return
	}
	$WingetUrl = "https://github.com/microsoft/winget-cli/releases/"
	if ($null -eq (Get-AppxPackage "Microsoft.UI.Xaml.2.8*" -AllUsers)) {
		Write-Verbose "Downloading Microsoft UI XAML..."
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

	Connect-MSGraph -Scopes @("UserAuthenticationMethod.ReadWrite.All")
	Write-Output (New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $Email -BodyParameter ($reqBody | ConvertTo-Json)).TemporaryAccessPass
	(Disconnect-MgGraph) >nul
}

# Removes the Bad iManage Adobe Reader addin from a remote computer
function Remove-ReaderAddin {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$ComputerName
	)
	$AddinPath = "\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\plug_ins\IManAcrobatReader10.api"

	Test-ElevatedPrivilege
	Write-Verbose "Checking if Adobe Reader is installed..."
	$ReaderInstalled = $false
	$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName) # Gets remote HKLM Base Key
	if ($null -eq $BaseKey) { throw "Unable to open connection to remote computer. Exiting..." }
	$32BitKeys = $BaseKey.OpenSubKey("Software\wow6432node\microsoft\Windows\Currentversion\uninstall")
	foreach ($Key in $32BitKeys.GetSubKeyNames()) {
		$SubKey = $32BitKeys.OpenSubKey($Key)
		if ($SubKey.GetValue("DisplayName") -like "*Reader*") {
			Write-Verbose "Adobe Reader Located!"
			$ReaderInstalled = $true
			$SubKey.Close()
			break
		}
		$SubKey.Close()
	}
	$32BitKeys.Close()
	$BaseKey.Close()

	if (-not $ReaderInstalled) {
		do {
			$Response = Read-Host -Prompt "Adobe Reader is not installed. Continue Anyway? [Y/N]"
		} until (($Response -eq 'n') -or ($Response -eq 'y'))
		if ($Response -eq 'n') { Write-Verbose "Exiting..."; return }
	}

	Write-Verbose "Checking for corrupt addin file..."
	if (Test-Path ("\\" + $ComputerName + "\c$" + $AddinPath)) {
		Write-Verbose "Located! Attempting to remove the addin from $ComputerName..."
		while ((Test-Path ("\\" + $ComputerName + "\c$" + $AddinPath))) {
			Remove-Item -Force ("\\" + $ComputerName + "\c$" + $AddinPath)
		}
	} else {
		Write-Verbose "Reader Addin not detected. Exiting..."
		return
	}

	# Final Check
	if (-not (Test-Path ("\\" + $ComputerName + "\c$" + $AddinPath))) {
		Write-Output "Reader addin successfully removed!"
	}
}

# Removes old RSA VPN configs from a remote machine
function Remove-RSA {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[String]$ComputerName
	)
	$FilesToRemove = @("DCXFX.xml","DCAFX.xml","DCWFX.xml","PHQFX.xml","DCXDirect.xml")
	$FilePath = "\\" + $ComputerName + "\c$\ProgramData\Cisco\Cisco Secure Client\VPN\Profile"
	Test-ElevatedPrivilege
	Write-Verbose "Checking for files..."
	$FilesToRemove | ForEach-Object {
		if (Test-Path ($FilePath + "\" + $_)) {
			Write-Verbose "Located $_, attempting to remove..."
			while (Test-Path ($FilePath + "\" + $_)) {
				Remove-Item -Force ($FilePath + "\" + $_)
			}
			# Verify file is actually removed
			if (-not (Test-Path ($FilePath + "\" + $_))) {
				Write-Verbose "$_ successfully removed!"
			}
		} else {
			Write-Verbose "$_ not found, skipping..."
		}
	}
	Write-Output "All configurations successfully removed!"
}

# Removes Windows Hello pin from the current computer
# Probably just needs to be rewritten in CMD/Batch? Or call CMD through PowerShell in a persistant session. Hmm.
function Remove-WindowsHelloPin {
	Test-ElevatedPrivilege
	takeown /f "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" /r /d y >nul
	icacls "C:\WINDOWS\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" /reset /t /c /l /q
	Remove-Item -Path "C:\WINDOWS\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" -Recurse -Force
}

# Restarts Onelog on the current computer
function Restart-OneLog {
	$Path = "\ITS\OneLog\Client\LoginApplication.exe"
	$Service = Get-Service -Name "ITS Onelog Client"
	if ($Service.Status -eq "Running") {
		Restart-Service -InputObject $Service -Force
	} else {
		Start-Service -InputObject $Service
	}
	Get-Process -Name LoginApplication | Stop-Process
	if (Test-Path -Path "$ENV:ProgramFiles$Path") {
		& "$ENV:ProgramFiles$Path"
	} elseif (Test-Path -Path "${ENV:ProgramFiles(x86)}$Path") {
		& "${ENV:ProgramFiles(x86)}$Path"
	}
}

function Resize-Video {
	[CmdletBinding(DefaultParameterSetName = "AbsoluteEndTime")]
	param (
		[Parameter()]
		[ValidatePattern("(\d{1,2}:)+\d{2}")]
		[String]$StartTime = "00:00:00",
		[Parameter(ParameterSetName = "AbsoluteEndTime", Mandatory)]
		[ValidatePattern("(\d{1,2}:)+\d{2}")]
		[String]$EndTime,
		[Parameter(ParameterSetName = "RelativeEndTime")]
		[Int]$TrimSeconds = 0,
		[Parameter(Mandatory)]
		[ValidateScript({
				if ((Get-PSDrive HKCR -ErrorAction SilentlyContinue) -eq "") { New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT }
				if (-not (Test-Path -Path $_)) { throw "Input does not exist" }
				elseif ( -not (Test-Path -Path $_ -PathType Leaf)) { throw "Input is not a file" }
				else { return $true }
			})]
		[String]$InputPathString,
		[Parameter(Mandatory)]
		[ValidateScript({
				if (-not (Test-Path -Path $_ -IsValid)) { throw "Output Path is Invalid" }
				elseif (-not ($_ -match ".*\.(\w{3,})$")) { throw "Output Path is not a file!" }
				else { return $true }
			})]
		[String]$OutputPathString
	)

	# Check if ffmpeg/ffprobe are installed
	if ((Get-Command ffmpeg -ErrorAction SilentlyContinue) -eq "") { throw "ffmpeg is not installed. Install ffmpeg to use this command." }
	if ((Get-Command ffprobe -ErrorAction SilentlyContinue) -eq "") { throw "ffprobe is not installed. Install ffmpeg to use this command." }

	# Parse paths
	$InputPath = Resolve-Path -Path $InputPathString
	Resolve-Path -Path $OutputPathString -ErrorAction SilentlyContinue -ErrorVariable _resolvepath
	$OutputPath = $_resolvepath[0].TargetObject

	# Verify file is actually a video
	if (((ffprobe -count_packets -show_entries stream=nb_read_packets -output_format json -v 0 $InputPath) | ConvertFrom-Json).streams.nb_read_packets -eq 1) { throw "File is not a video" }

	# Calculate EndTime if unset
	if ($null -eq $EndTime) { $EndTime = ([math]::floor([decimal](ffprobe -v fatal -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 $InputPath)) - $TrimSeconds) }

	ffmpeg -ss $StartTime -to $EndTime -i $InputPath $OutputPath
}

# Checks AD for users who have Adobe Licenses
function Test-AdobeLicense {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$SearchFor
	)
	(Get-ADGroup -Identity "Adobe Pro Licensed Users" -Properties Member).Member | Select-String -Pattern $SearchFor
}

# Checks if the current session is running as Admin
function Test-ElevatedPrivilege {
	[CmdletBinding()]
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal $identity
	if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		throw "Not running with elevated privileges"
	}
}

# Checks if Exchange Online Powershell is currently connected
function Test-EXOConnection {
	if ($null -ne (Get-ConnectionInformation)) {
		Write-Verbose "Exchange Online already connected. Disconnecting..."
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
	Connect-EXO
	$Mailbox = Get-EXOMailbox -Identity $Email 2>nul
	Disconnect-ExchangeOnline -Confirm:$false

	if ($Mailbox) {
		Write-Output "$Email is on Exchange Online"
	} else {
		Write-Output "$Email is NOT on Exchange Online"
	}
}

# Checks if Microsoft Graph is connected
function Test-MgGraph {
	if ($null -ne (Get-MgContext)) {
		Write-Verbose "Microsoft Graph already connected. Disconnecting..."
		Disconnect-MgGraph >nul
	}
}

# Quick test which returns a boolean for if a string is a UUID or not.
function Test-UUID {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[String]$InputString
	)
	return $InputString -match "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
}
