# Copies exhibit stamps file from network share to stamps folder for user.
# Works remotely
function Add-ExhibitStamps {
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
	$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -Split "\\"
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

	If (Test-Path -Path "~\graphToken") {
		Connect-MgGraph -AccessToken (Get-Content ~\graphToken | ConvertTo-SecureString -AsPlainText -Force) -NoWelcome
	} Else {
		If ($null -ne $Scopes) {
			Connect-MgGraph -Scopes $Scopes -NoWelcome
		} Else {
			Connect-MgGraph -NoWelcome
		}
	}
}

# Gets members of a distribution list and translates to email addresses.
# Currently nonfunctional due to Module requirements.
# function Get-DistroMembers {
# 	[CmdletBinding()]
# 	param (
# 		[Parameter(Mandatory)]
# 		[String]$Group
# 	)
# 	(Get-DistributionGroupMember -Identity $Group).Name | ForEach-Object { Write-Host (Get-AzADUser -StartsWith $_.Substring(0,($_.Length - 3)).Replace("'","''") ).Mail }
# }

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

	$Server = (Get-ADDomainController -DomainName $Domain -Discover -NextClosestSite).HostName | Out-String -NoNewline
	Try {
		Get-ADUser -Server $Server -Identity $UserName -Properties DisplayName, msDS-UserPasswordExpiryTimeComputed |
		Select-Object -Property Displayname,@{Name = "Expiration Date";Expression = { [datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed") } }
	} Catch {
		Throw "User is not in domain $Domain!"
	}
}

# Installs the latest version of Winget onto the current computer
function Install-WinGet {
	If ($null -ne (Get-Command "winget" -ErrorAction SilentlyContinue)) {
		Write-Host "Winget is already installed."
		Return
	}
	$WingetUrl = "https://github.com/microsoft/winget-cli/releases/"
	If ($null -eq (Get-AppxPackage "Microsoft.UI.Xaml.2.8*" -AllUsers)) {
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
	Write-Host (New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $Email -BodyParameter ($reqBody | ConvertTo-Json)).TemporaryAccessPass
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

	Test-ElevatedPrivileges
	Write-Verbose "Checking if Adobe Reader is installed..."
	$ReaderInstalled = $false
	$BaseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ComputerName) # Gets remote HKLM Base Key
	If ($null -eq $BaseKey) { Throw "Unable to open connection to remote computer. Exiting..." }
	$32BitKeys = $BaseKey.OpenSubKey("Software\wow6432node\microsoft\Windows\Currentversion\uninstall")
	ForEach ($Key in $32BitKeys.GetSubKeyNames()) {
		$SubKey = $32BitKeys.OpenSubKey($Key)
		If ($SubKey.GetValue("DisplayName") -like "*Reader*") { 
			Write-Verbose "Adobe Reader Located!"
			$ReaderInstalled = $true
			$SubKey.Close()
			Break
		}
		$SubKey.Close()
	}
	$32BitKeys.Close()
	$BaseKey.Close()

	If (-not $ReaderInstalled) {
		Do {
			$Response = Read-Host -Prompt "Adobe Reader is not installed. Continue Anyway? [Y/N]"
		} Until (($Response -eq 'n') -or ($Response -eq 'y'))
		If ($Response -eq 'n') { Write-Verbose "Exiting..."; Return }
	}

	Write-Verbose "Checking for corrupt addin file..."
	If (Test-Path ("\\" + $ComputerName + "\c$" + $AddinPath)) {
		Write-Verbose "Located! Attempting to remove the addin from $ComputerName..."
		While ((Test-Path ("\\" + $ComputerName + "\c$" + $AddinPath))) {
			Remove-Item -Force ("\\" + $ComputerName + "\c$" + $AddinPath)
		}
	} Else {
		Write-Verbose "Reader Addin not detected. Exiting..."
		Return
	}

	# Final Check
	If (-not (Test-Path ("\\" + $ComputerName + "\c$" + $AddinPath))) {
		Write-Host "Reader addin successfully removed!"
	}
}

# Removes Windows Hello pin from the current computer
# Probably just needs to be rewritten in CMD/Batch? Or call CMD through PowerShell in a persistant session. Hmm.
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
				If (Get-PSDrive HKCR -ErrorAction SilentlyContinue -eq "") { New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT }
				If (-not (Test-Path -Path $_)) { Throw "Input does not exist" }
				ElseIf ( -not (Test-Path -Path $_ -PathType Leaf)) { Throw "Input is not a file" }
				Else { Return $true }
			})]
		[String]$InputPathString,
		[Parameter(Mandatory)]
		[ValidateScript({
				If (-not (Test-Path -Path $_ -IsValid)) { Throw "Output Path is Invalid" }
				ElseIf (-not ($_ -match ".*\.(\w{3,})$")) { Throw "Output Path is not a file!" }
				Else { Return $true }
			})]
		[String]$OutputPathString
	)

	# Check if ffmpeg/ffprobe are installed
	If ((Get-Command ffmpeg -ErrorAction SilentlyContinue) -eq "") { Throw "ffmpeg is not installed. Install ffmpeg to use this command." }
	If ((Get-Command ffprobe -ErrorAction SilentlyContinue) -eq "") { Throw "ffprobe is not installed. Install ffmpeg to use this command." }

	# Parse paths
	$InputPath = Resolve-Path -Path $InputPathString
	Resolve-Path -Path $OutputPathString -ErrorAction SilentlyContinue -ErrorVariable _resolvepath
	$OutputPath = $_resolvepath

	# Verify file is actually a video
	If (((ffprobe -count_packets -show_entries stream=nb_read_packets -output_format json -v 0 $InputPath) | ConvertFrom-Json).streams.nb_read_packets -eq 1) { Throw "File is not a video" }

	# Calculate EndTime if unset
	If ($null -eq $EndTime) { $EndTime = ([math]::floor([decimal](ffprobe -v fatal -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 $InputPath)) - $TrimSeconds) }

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
function Test-ElevatedPrivileges {
	[CmdletBinding()]
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal $identity
	If (-Not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		Throw "Not running with elevated privileges"
	}
}

# Checks if Exchange Online Powershell is currently connected
function Test-EXOConnection {
	If ($null -ne (Get-ConnectionInformation)) {
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
	
	If ($Mailbox) {
		Write-Host "$Email is on Exchange Online"
	} Else {
		Write-Host "$Email is NOT on Exchange Online"
	}
}

# Checks if Microsoft Graph is connected
function Test-MgGraph {
	If ($null -ne (Get-MgContext)) {
		Write-Verbose "Microsoft Graph already connected. Disconnecting..."
		Disconnect-MgGraph >nul
	}
}