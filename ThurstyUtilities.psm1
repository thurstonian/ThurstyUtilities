function Add-ExhibitStamps {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[String]$ComputerName,
		[Parameter(Mandatory)]
		[String]$UserName
	)
	Copy-Item -Path "\\cozen\deploy\source\Adobe\Pro DC\Exhibit Stamp\Exhibit-Stamp.pdf" -Destination "\\$ComputerName\c$\Users\$UserName\Adobe\Acrobat\DC\Stamps"
}

function Connect-EXO {
	$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -Split "\\"
	Connect-ExchangeOnline -UserPrincipalName ("" + $Identity[1] + "@" + $Identity[1] + ".com") -ShowBanner:$false
}

function Import-Dependency {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$Dependency
	)
	Install-Module -Name $Dependency
	If ($null -eq (Get-Module -Name "$Dependency*")) {
		Import-Module -Name $Dependency
	}
}

function Install-AdminTools {
	Set-DefaultPSRepository
	Install-WinGet
	Import-Dependency Microsoft.Graph
	Import-Dependency ExchangeOnlineManagement
}

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

function Remove-WindowsHelloPin {
	Test-ElevatedPrivileges
	takeown /f "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" /r /d y >nul
	icacls "C:\WINDOWS\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" /reset /t /c /l /q
	Remove-Item -Path "C:\WINDOWS\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc" -Recurse -Force
}

function Set-DefaultPSRepository {
	If ($null -eq (Get-PSRepository -Name "PSGallery")) {
		If (((Get-Host).Version).Major -gt 5) {
			Register-PSRepository -Default -InstallationPolicy Trusted
		} Else {
			Register-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2/ -InstallationPolicy Trusted
		}
	}
	If ((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
		Set-PSRepository -Name "PSGallery" -InstallationPolicy "Trusted"
	}
}

function Set-LAPSPassword {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[String]$ComputerName
	)

	$Password = Get-LapsADPassword $ComputerName -AsPlainText
	Write-Host ("Password: " + $Password.Password)
	Write-Host ("Expiration: " + $Password.ExpirationTimestamp)
}

function Stop-Umbrella {
	Test-ElevatedPrivileges
	Get-Service -Name "*umbrellaagent*" | Where-Object { $_.Status -eq "Running" } | Stop-Service
	Get-Service -Name "*swgagent*" | Where-Object { $_.Status -eq "Running" } | Stop-Service
}

function Test-AdobeLicense {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]	
		[String]$SearchFor
	)
    (Get-ADGroup -Identity "Adobe Pro Licensed Users" -Properties Member).Member | Select-String -Pattern $SearchFor
}

function Test-ElevatedPrivileges {
	[CmdletBinding()]
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal $identity
	If (-Not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		throw "Not running with elevated privileges"
	}
}

function Test-MgGraph {
	If ($null -eq (Get-Module -Name Microsoft.Graph*)) {
		throw "Microsoft Graph is not initialized; Install the PowerShell module or run Install-AdminTools"
	} ElseIf ($null -ne (Get-MgContext)) {
		Write-Error "Microsoft Graph already connected. Disconnecting..."
		Disconnect-MgGraph >nul
	}
}
