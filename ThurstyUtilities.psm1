function Test-ElevatedPrivileges {
	[CmdletBinding()]
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal $identity
	If (-Not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		throw "Not running with elevated privileges"
	}
}

function Test-AdobeLicense {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]	
		[string]$LastName
	)
    (Get-ADGroup -Identity "Adobe Pro Licensed Users" -Properties Member).Member | Select-String -Pattern $LastName
}

function Remove-ReaderAddin {
	Test-ElevatedPrivileges
	If ($null -ne (Get-ItemProperty -Path "HKLM:\Software\wow6432node\microsoft\Windows\Currentversion\uninstall\*", "HKLM:\Software\microsoft\Windows\Currentversion\uninstall\*" |
			Where-Object { $_.DisplayName -like "*Reader*" })) {
		If (Test-Path "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\plug_ins\IManAcrobatReader10.api") {
			Remove-Item -Force "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\plug_ins\IManAcrobatReader10.api"
		}
	}
}

function Register-DefaultPSRepository {
	If ($null -eq (Get-PSRepository -Name "PSGallery")) {
		If (((Get-Host).Version).Major -gt 5) {
			Register-PSRepository -Default -InstallationPolicy Trusted
		}
		Else {
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
		[string]$PCName
	)

	$password = get-adcomputer $PCName -properties * | Select-Object ms-mcs-a*
	$ExpirationTime = w32tm -ntte $password.'ms-Mcs-AdmPwdExpirationTime'
	Write-Host "Password:" $password.'ms-Mcs-AdmPwd'
	Write-host "Expiration:" $ExpirationTime
}

function Install-WinGet {
	$WingetUrl = "https://github.com/microsoft/winget-cli/releases/"
	If (($null -eq (Get-AppxPackage "Microsoft.UI.Xaml.2.7*" -AllUsers)) -and ($null -eq (Get-AppxPackage "Microsoft.UI.Xaml.2.8*" -AllUsers))) {
		Write-Host "Downloading Microsoft UI XAML..."
		Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml" -OutFile ($env:TEMP + "xaml.zip")
		Expand-Archive -LiteralPath ($AdminPath + "xaml.zip") -DestinationPath ($env:TEMP + "xaml")
		Add-AppxPackage ($env:TEMP + "xaml\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.8.appx") -AllUsers
	}
	$WingetVersion = [System.Net.WebRequest]::Create($WingetUrl + "latest").GetResponse().ResponseUri.OriginalString.split('/')[-1].Trim('v')
	Invoke-WebRequest -Uri ($WingetUrl + "download/v" + $WingetVersion + "/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle") -OutFile ($env:TEMP + "winget.msixbundle")
	Add-AppxPackage ($env:TEMP + "winget.msixbundle")
}

function Install-AdminTools {
	Register-DefaultPSRepository
	Install-WinGet
}

function Stop-Umbrella {
	Test-ElevatedPrivileges
	Get-Service -Name "*umbrellaagent*" | Where-Object { $_.Status -eq "Running" } | Stop-Service
	Get-Service -Name "*swgagent*" | Where-Object { $_.Status -eq "Running" } | Stop-Service
}

function Add-ExhibitStamps {
	Copy-Item -Path "\\cozen\deploy\source\Adobe\Pro DC\Exhibit Stamp\Exhibit-Stamp.pdf" -Destination "$env:APPDATA\Adobe\Acrobat\DC\Stamps"
}